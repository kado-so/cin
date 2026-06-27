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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/kado-so/cin/internal/config"
	"github.com/kado-so/cin/internal/cryptoage"
	"github.com/kado-so/cin/internal/doctor"
	"github.com/kado-so/cin/internal/envelope"
	"github.com/kado-so/cin/internal/localenv"
	"github.com/kado-so/cin/internal/resolve"
	cinschema "github.com/kado-so/cin/internal/schema"
	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var version = "0.0.0-dev"

const (
	groupProject     = "project"
	groupConfig      = "config"
	groupRuntime     = "runtime"
	groupUsers       = "users"
	groupDiagnostics = "diagnostics"
)

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
		Use:   "cin",
		Short: "Encrypt app config in Git and inject it at runtime.",
		Long:  "cin (config inject) encrypts config in Git and injects resolved values at runtime.",
		Example: `  # Create configs.secret.yaml at the repo root
  cin init vaishnav

  # Set, read, and edit root config
  cin set -e dev options.postgres.host postgres
  cin get -e dev options.postgres.host
  cin edit -e dev

  # Set and run app config
  cin set -e dev -a api DATABASE_URL 'postgres://{{ .options.postgres.host }}/api'
  cin run -e dev -a api -- pnpm dev

  # Manage users
  cin users create alice
  cin users list
  cin users approve alice

  # Check config health
  cin doctor -e dev -a api`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return localenv.Load()
		},
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

	versionCmd := &cobra.Command{
		Use:     "version",
		Short:   "Show the cin version",
		GroupID: groupDiagnostics,
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(stdout, version)
		},
	}
	initCmd := newInitCommand(stdout, &filePath)
	initCmd.GroupID = groupProject
	setCmd := newSetCommand(&filePath)
	setCmd.GroupID = groupConfig
	getCmd := newGetCommand(stdout, &filePath, &localFile, &noLocal, &user)
	getCmd.GroupID = groupConfig
	editCmd := newEditCommand(&filePath, &user)
	editCmd.GroupID = groupConfig
	explainCmd := newExplainCommand(stdout, &filePath, &localFile, &noLocal, &user)
	explainCmd.GroupID = groupConfig
	runCmd := newRunCommand(stdout, stderr, &filePath, &localFile, &noLocal, &user)
	runCmd.GroupID = groupRuntime
	exportCmd := newExportCommand(stdout, stderr, &filePath, &localFile, &noLocal, &user)
	exportCmd.GroupID = groupRuntime
	usersCmd := newUsersCommand(stdout, stderr, &filePath, &user)
	usersCmd.GroupID = groupUsers
	doctorCmd := newDoctorCommand(stdout, &filePath, &localFile, &noLocal, &user)
	doctorCmd.GroupID = groupDiagnostics

	root.AddGroup(
		&cobra.Group{ID: groupProject, Title: "Project commands"},
		&cobra.Group{ID: groupConfig, Title: "Config commands"},
		&cobra.Group{ID: groupRuntime, Title: "Runtime commands"},
		&cobra.Group{ID: groupUsers, Title: "User commands"},
		&cobra.Group{ID: groupDiagnostics, Title: "Diagnostics commands"},
	)
	root.AddCommand(initCmd, setCmd, getCmd, editCmd, explainCmd, runCmd, exportCmd, usersCmd, doctorCmd, versionCmd)

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
		Use:     "users",
		Aliases: []string{"user"},
		Short:   "Manage cin users",
		Example: `  cin users create alice
  cin users list
  cin users approve alice
  cin users remove alice`,
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
		Use:     "create <username>",
		Aliases: []string{"add"},
		Short:   "Create a pending user",
		Args:    cobra.ExactArgs(1),
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
			if env == "" {
				return errors.New("environment is required")
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
			if secretPath(path) {
				enc, err := encryptedValue(doc, env, path, recipientSet, value)
				if err != nil {
					return err
				}
				if err := doc.SetScalar(path, enc); err != nil {
					return err
				}
			} else {
				if recipientSet != "" {
					return errors.New("--recipient-set only applies to secret values")
				}
				if err := doc.SetScalar(path, value); err != nil {
					return err
				}
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
			env = effectiveEnv(doc, env)
			key := args[0]
			path, err := targetPath(env, app, key)
			if err != nil {
				return err
			}
			if !secretPath(path) {
				value, ok := doc.GetScalar(path)
				if !ok {
					return missingValueError(doc, env, app, key)
				}
				fmt.Fprintln(stdout, value)
				return nil
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
				fmt.Fprintln(stdout, "[secret]")
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
			fmt.Fprintln(stdout, resolvedValue.Resolved)
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

func newExportCommand(stdout io.Writer, stderr io.Writer, filePath *string, localFile *string, noLocal *bool, user *string) *cobra.Command {
	var env string
	var app string
	var format string
	var out string
	var yes bool
	var toStdout bool
	var redactValues bool

	cmd := &cobra.Command{
		Use:   "export -e <env> -a <app>",
		Short: "Export resolved app config",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if app == "" {
				return errors.New("cin export requires -a <app>\nfix: rerun with -a api")
			}
			if out != "" && toStdout {
				return errors.New("choose either --out or --stdout")
			}
			if !redactValues && out != "" && !yes {
				return fmt.Errorf("refusing to write plaintext secrets to %s without confirmation\nfix: rerun with --yes", out)
			}
			if !redactValues && toStdout && !yes {
				return errors.New("refusing to write plaintext secrets to stdout without confirmation\nfix: rerun with --stdout --yes")
			}
			envVars, err := resolvedAppEnv(*filePath, *localFile, *noLocal, *user, env, app)
			if err != nil {
				return err
			}
			if redactValues {
				redactEnv(envVars)
			}
			data, err := formatExport(envVars, format)
			if err != nil {
				return err
			}
			if toStdout || (redactValues && out == "") {
				_, err = stdout.Write(data)
				return err
			}
			if out == "" {
				return pageSecret(data, cmd.InOrStdin(), stdout, stderr)
			}
			return writeSecretFile(out, data)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
	cmd.Flags().StringVar(&format, "format", "dotenv", "output format: dotenv or json")
	cmd.Flags().StringVar(&out, "out", "", "write output to file")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm plaintext file output")
	cmd.Flags().BoolVar(&toStdout, "stdout", false, "write plaintext output to stdout")
	cmd.Flags().BoolVar(&redactValues, "redact-values", false, "replace exported values with redacted markers")
	return cmd
}

func newEditCommand(filePath *string, user *string) *cobra.Command {
	var env string
	var app string

	cmd := &cobra.Command{
		Use:   "edit [-e <env>] [-a <app>]",
		Short: "Edit config values in a secure temp file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			if app != "" && env == "" {
				return errors.New("environment is required when using -a")
			}
			data, err := renderEditDocument(doc, env, app, identities)
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
			changed, changedEnvs, err := applyEditDocument(doc, env, app, identities, editedData)
			if err != nil {
				return err
			}
			if !changed {
				return nil
			}
			if err := validateEditedScope(doc, *filePath, changedEnvs, app, identities); err != nil {
				return err
			}
			return doc.Save(*filePath)
		},
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "environment")
	cmd.Flags().StringVarP(&app, "app", "a", "", "app")
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
			env = effectiveEnv(doc, env)
			key := args[0]
			path, err := targetPath(env, app, key)
			if err != nil {
				return err
			}
			if !secretPath(path) {
				value, ok := doc.GetScalar(path)
				if !ok {
					return missingValueError(doc, env, app, key)
				}
				fmt.Fprintln(stdout, key)
				fmt.Fprintf(stdout, "  source: %s\n", strings.Join(path, "."))
				fmt.Fprintln(stdout, "  kind: plaintext")
				fmt.Fprintf(stdout, "  value: %s\n", value)
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
			value, ok := result.Value(canonical)
			if !ok {
				return missingValueError(doc, env, app, key)
			}
			localDoc, err := loadLocalConfig(*localFile, *noLocal)
			if err != nil {
				return err
			}
			layers, err := explainLayers(doc, localDoc, env, strings.Split(canonical, "."))
			if err != nil {
				return err
			}
			source := "unknown"
			if last, ok := finalLayer(layers); ok {
				source = last.displayPath()
			}

			kind := "encrypted scalar"
			if value.Kind == envelope.Template {
				kind = "encrypted template"
			}
			fmt.Fprintln(stdout, key)
			fmt.Fprintf(stdout, "  source: %s\n", source)
			fmt.Fprintf(stdout, "  kind: %s\n", kind)
			fmt.Fprintf(stdout, "  recipientSet: %s\n", value.RecipientSet)
			if len(layers) > 0 {
				fmt.Fprintln(stdout, "  layers:")
				for i, layer := range layers {
					status := "overridden"
					if i == len(layers)-1 {
						status = "active"
					}
					fmt.Fprintf(stdout, "    %s %s %s\n", layer.scope(env), layer.displayPath(), status)
				}
			}
			if len(value.References) > 0 {
				fmt.Fprintln(stdout, "  references:")
				for _, ref := range value.References {
					refLayers, err := explainLayers(doc, localDoc, env, strings.Split(ref, "."))
					if err != nil {
						return err
					}
					refSource := "unknown"
					refScope := "unknown"
					if layer, ok := finalLayer(refLayers); ok {
						refSource = layer.displayPath()
						refScope = layer.scope(env)
					}
					fmt.Fprintf(stdout, "    %s ok secret source: %s %s\n", displayRef(app, ref), refScope, refSource)
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
	env = effectiveEnv(doc, env)
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
	env = effectiveEnv(doc, env)
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

func redactEnv(envVars map[string]string) {
	for key := range envVars {
		envVars[key] = "[secret]"
	}
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

func pageSecret(data []byte, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	tmp, cleanup, err := secureTempFile("export-*")
	if err != nil {
		return err
	}
	path := tmp.Name()
	defer cleanup()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	pager := pagerCommand()
	args := append(append([]string(nil), pager[1:]...), path)
	cmd := exec.Command(pager[0], args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return errors.New("failed to open export pager")
	}
	return nil
}

func pagerCommand() []string {
	pager := os.Getenv("PAGER")
	if pager == "" {
		pager = defaultPager()
	}
	fields := strings.Fields(pager)
	if len(fields) == 0 {
		return []string{defaultPager()}
	}
	return fields
}

func defaultPager() string {
	if runtime.GOOS == "windows" {
		return "more"
	}
	return "less"
}

func renderEditDocument(doc *config.Document, env, app string, identities []age.Identity) ([]byte, error) {
	var root *yaml.Node
	var omitted []string
	if env == "" {
		root = doc.CloneNode(nil)
		if root == nil {
			root = emptyYAMLMap()
		}
		var err error
		omitted, err = decryptRootSecrets(root, identities)
		if err != nil {
			return nil, err
		}
	} else if app == "" {
		var more []string
		var err error
		root, more, err = editableEnvNode(doc, env, identities)
		if err != nil {
			return nil, err
		}
		omitted = append(omitted, more...)
	} else {
		var more []string
		var err error
		root, more, err = editableAppNode(doc, env, app, identities)
		if err != nil {
			return nil, err
		}
		omitted = append(omitted, more...)
	}
	if len(omitted) > 0 {
		sort.Strings(omitted)
		root.HeadComment = "omitted undecryptable values:\n- " + strings.Join(omitted, "\n- ")
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

func decryptRootSecrets(root *yaml.Node, identities []age.Identity) ([]string, error) {
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("config root must be a map")
	}
	envs := yamlMapValue(root, "envs")
	if envs == nil {
		return nil, nil
	}
	if envs.Kind != yaml.MappingNode {
		return nil, errors.New("envs must be a map")
	}
	var omitted []string
	for i := 0; i < len(envs.Content); i += 2 {
		env := envs.Content[i].Value
		envNode := envs.Content[i+1]
		if envNode.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("environment must be a map: %s", env)
		}
		more, err := decryptEnvSecrets(envNode, env, identities)
		if err != nil {
			return nil, err
		}
		omitted = append(omitted, more...)
	}
	return omitted, nil
}

func editableEnvNode(doc *config.Document, env string, identities []age.Identity) (*yaml.Node, []string, error) {
	node := doc.CloneNode([]string{"envs", env})
	if node == nil {
		node = skeletonEnvNode()
	}
	if node.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("environment must be a map: %s", env)
	}
	omitted, err := decryptEnvSecrets(node, env, identities)
	return node, omitted, err
}

func editableAppNode(doc *config.Document, env, app string, identities []age.Identity) (*yaml.Node, []string, error) {
	node := doc.CloneNode([]string{"envs", env, "apps", app})
	if node == nil {
		node = skeletonAppNode()
	}
	if node.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("app must be a map: %s", app)
	}
	omitted, err := decryptAppSecrets(node, env, app, identities)
	return node, omitted, err
}

func decryptEnvSecrets(envNode *yaml.Node, env string, identities []age.Identity) ([]string, error) {
	var omitted []string
	if options := yamlMapValue(envNode, "options"); options != nil {
		more, err := decryptOptions(options, []string{"envs", env, "options"}, identities)
		if err != nil {
			return nil, err
		}
		omitted = append(omitted, more...)
	}
	if apps := yamlMapValue(envNode, "apps"); apps != nil {
		if apps.Kind != yaml.MappingNode {
			return nil, errors.New("apps must be a map")
		}
		for i := 0; i < len(apps.Content); i += 2 {
			app := apps.Content[i].Value
			appNode := apps.Content[i+1]
			if appNode.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("apps.%s must be a map", app)
			}
			more, err := decryptAppSecrets(appNode, env, app, identities)
			if err != nil {
				return nil, err
			}
			omitted = append(omitted, more...)
		}
	}
	return omitted, nil
}

func decryptAppSecrets(appNode *yaml.Node, env, app string, identities []age.Identity) ([]string, error) {
	values := yamlMapValue(appNode, "values")
	if values == nil {
		return nil, nil
	}
	if values.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("apps.%s.values must be a map", app)
	}
	return decryptSecretValues(values, []string{"envs", env, "apps", app, "values"}, identities)
}

func decryptOptions(node *yaml.Node, path []string, identities []age.Identity) ([]string, error) {
	if node.Kind != yaml.MappingNode {
		return nil, errors.New("options must be a map")
	}
	var omitted []string
	for i := 0; i < len(node.Content); {
		key := node.Content[i].Value
		value := node.Content[i+1]
		nextPath := append(path, key)
		if value.Kind == yaml.MappingNode {
			more, err := decryptOptions(value, nextPath, identities)
			if err != nil {
				return nil, err
			}
			omitted = append(omitted, more...)
			i += 2
			continue
		}
		ok, err := decryptSecretNode(value, strings.Join(nextPath, "."), identities)
		if err != nil {
			return nil, err
		}
		if !ok {
			omitted = append(omitted, strings.Join(nextPath, "."))
			node.Content = append(node.Content[:i], node.Content[i+2:]...)
			continue
		}
		i += 2
	}
	return omitted, nil
}

func decryptSecretValues(node *yaml.Node, path []string, identities []age.Identity) ([]string, error) {
	var omitted []string
	for i := 0; i < len(node.Content); {
		key := node.Content[i].Value
		value := node.Content[i+1]
		nextPath := append(path, key)
		ok, err := decryptSecretNode(value, strings.Join(nextPath, "."), identities)
		if err != nil {
			return nil, err
		}
		if !ok {
			omitted = append(omitted, strings.Join(nextPath, "."))
			node.Content = append(node.Content[:i], node.Content[i+2:]...)
			continue
		}
		i += 2
	}
	return omitted, nil
}

func decryptSecretNode(node *yaml.Node, path string, identities []age.Identity) (bool, error) {
	if node.Kind != yaml.ScalarNode {
		return false, fmt.Errorf("%s must be an encrypted scalar", path)
	}
	plaintext, _, decryptable, err := editablePlaintext(node.Value, path, identities)
	if err != nil || !decryptable {
		return decryptable, err
	}
	*node = *yamlScalar(plaintext)
	return true, nil
}

func applyEditDocument(doc *config.Document, env, app string, identities []age.Identity, data []byte) (bool, []string, error) {
	root, err := parseEditedYAML(data)
	if err != nil {
		return false, nil, err
	}
	if env == "" {
		return applyRootNode(doc, root, identities)
	}
	if app != "" {
		changed, err := applyAppNode(doc, env, app, root, identities)
		if changed {
			return true, []string{env}, err
		}
		return false, nil, err
	}
	changed, err := applyEnvNode(doc, env, root, identities)
	if changed {
		return true, []string{env}, err
	}
	return false, nil, err
}

func applyRootNode(doc *config.Document, node *yaml.Node, identities []age.Identity) (bool, []string, error) {
	if node.Kind != yaml.MappingNode {
		return false, nil, errors.New("config root must be a map")
	}
	edited := cloneYAMLNode(node)
	if err := encryptRootSecrets(doc, edited, identities); err != nil {
		return false, nil, err
	}
	if err := preserveUndecryptableRootSecrets(doc, edited, identities); err != nil {
		return false, nil, err
	}
	before := doc.CloneNode(nil)
	if yamlNodeString(before) == yamlNodeString(edited) {
		return false, nil, nil
	}
	doc.ReplaceRoot(edited)
	return true, editedEnvNames(edited), nil
}

func parseEditedYAML(data []byte) (*yaml.Node, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("edited document is not valid YAML")
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("edited document must be a map")
	}
	return root.Content[0], nil
}

func applyEnvNode(doc *config.Document, env string, node *yaml.Node, identities []age.Identity) (bool, error) {
	if node.Kind != yaml.MappingNode {
		return false, fmt.Errorf("environment must be a map: %s", env)
	}
	edited := cloneYAMLNode(node)
	if err := encryptEnvSecrets(doc, env, edited, identities); err != nil {
		return false, err
	}
	if err := preserveUndecryptableSecrets(doc, env, edited, identities); err != nil {
		return false, err
	}
	before := doc.CloneNode([]string{"envs", env})
	if before == nil && emptyMapping(edited) {
		return false, nil
	}
	if yamlNodeString(before) == yamlNodeString(edited) {
		return false, nil
	}
	return true, doc.SetNode([]string{"envs", env}, edited)
}

func applyAppNode(doc *config.Document, env, app string, node *yaml.Node, identities []age.Identity) (bool, error) {
	if node.Kind != yaml.MappingNode {
		return false, fmt.Errorf("app must be a map: %s", app)
	}
	edited := cloneYAMLNode(node)
	if err := encryptAppSecrets(doc, env, app, edited, identities, doc.EnvDefaultRecipientSet(env)); err != nil {
		return false, err
	}
	if err := preserveUndecryptableAppSecrets(doc, env, app, edited, identities); err != nil {
		return false, err
	}
	before := doc.CloneNode([]string{"envs", env, "apps", app})
	if before == nil && emptyMapping(edited) {
		return false, nil
	}
	if yamlNodeString(before) == yamlNodeString(edited) {
		return false, nil
	}
	return true, doc.SetNode([]string{"envs", env, "apps", app}, edited)
}

func encryptRootSecrets(doc *config.Document, root *yaml.Node, identities []age.Identity) error {
	envs := yamlMapValue(root, "envs")
	if envs == nil {
		return nil
	}
	if envs.Kind != yaml.MappingNode {
		return errors.New("envs must be a map")
	}
	for i := 0; i < len(envs.Content); i += 2 {
		env := envs.Content[i].Value
		envNode := envs.Content[i+1]
		if envNode.Kind != yaml.MappingNode {
			return fmt.Errorf("environment must be a map: %s", env)
		}
		if err := encryptEnvSecrets(doc, env, envNode, identities); err != nil {
			return err
		}
	}
	return nil
}

func encryptEnvSecrets(doc *config.Document, env string, envNode *yaml.Node, identities []age.Identity) error {
	envDefaultSet := envDefaultRecipientSet(envNode)
	if options := yamlMapValue(envNode, "options"); options != nil {
		if err := encryptOptions(doc, env, []string{"envs", env, "options"}, options, identities, envDefaultSet); err != nil {
			return err
		}
	}
	if apps := yamlMapValue(envNode, "apps"); apps != nil {
		if apps.Kind != yaml.MappingNode {
			return errors.New("apps must be a map")
		}
		for i := 0; i < len(apps.Content); i += 2 {
			app := apps.Content[i].Value
			appNode := apps.Content[i+1]
			if err := encryptAppSecrets(doc, env, app, appNode, identities, envDefaultSet); err != nil {
				return err
			}
		}
	}
	return nil
}

func encryptAppSecrets(doc *config.Document, env, app string, appNode *yaml.Node, identities []age.Identity, envDefaultSet string) error {
	if appNode.Kind != yaml.MappingNode {
		return fmt.Errorf("apps.%s must be a map", app)
	}
	values := yamlMapValue(appNode, "values")
	if values == nil {
		return nil
	}
	if values.Kind != yaml.MappingNode {
		return fmt.Errorf("apps.%s.values must be a map", app)
	}
	for i := 0; i < len(values.Content); i += 2 {
		path := []string{"envs", env, "apps", app, "values", values.Content[i].Value}
		if err := encryptSecretNode(doc, env, path, values.Content[i+1], identities, envDefaultSet); err != nil {
			return err
		}
	}
	return nil
}

func encryptOptions(doc *config.Document, env string, path []string, node *yaml.Node, identities []age.Identity, envDefaultSet string) error {
	if node.Kind != yaml.MappingNode {
		return errors.New("options must be a map")
	}
	for i := 0; i < len(node.Content); i += 2 {
		nextPath := append(path, node.Content[i].Value)
		value := node.Content[i+1]
		if value.Kind == yaml.MappingNode {
			if err := encryptOptions(doc, env, nextPath, value, identities, envDefaultSet); err != nil {
				return err
			}
			continue
		}
		if err := encryptSecretNode(doc, env, nextPath, value, identities, envDefaultSet); err != nil {
			return err
		}
	}
	return nil
}

func encryptSecretNode(doc *config.Document, env string, path []string, node *yaml.Node, identities []age.Identity, envDefaultSet string) error {
	value, err := editNodeText(node)
	if err != nil {
		return err
	}
	if existing, ok := doc.GetScalar(path); ok {
		plaintext, _, decryptable, err := editablePlaintext(existing, strings.Join(path, "."), identities)
		if err == nil && decryptable && plaintext == value {
			*node = *yamlScalar(existing)
			return nil
		}
	}
	enc, err := encryptedEditedValue(doc, env, path, value, envDefaultSet)
	if err != nil {
		return err
	}
	*node = *yamlScalar(enc)
	return nil
}

func preserveUndecryptableRootSecrets(doc *config.Document, root *yaml.Node, identities []age.Identity) error {
	for _, ref := range doc.ValueRefs() {
		envNode := yamlLookup(root, []string{"envs", ref.Env})
		if envNode == nil {
			continue
		}
		if yamlLookup(root, ref.Path) != nil {
			continue
		}
		_, _, decryptable, err := editablePlaintext(ref.Raw, strings.Join(ref.Path, "."), identities)
		if err != nil {
			return err
		}
		if !decryptable {
			setYAMLPath(root, ref.Path, yamlScalar(ref.Raw))
		}
	}
	return nil
}

func preserveUndecryptableSecrets(doc *config.Document, env string, envNode *yaml.Node, identities []age.Identity) error {
	for _, ref := range doc.ValueRefs() {
		if ref.Env != env {
			continue
		}
		if yamlLookup(envNode, ref.Path[2:]) != nil {
			continue
		}
		_, _, decryptable, err := editablePlaintext(ref.Raw, strings.Join(ref.Path, "."), identities)
		if err != nil {
			return err
		}
		if !decryptable {
			setYAMLPath(envNode, ref.Path[2:], yamlScalar(ref.Raw))
		}
	}
	return nil
}

func preserveUndecryptableAppSecrets(doc *config.Document, env, app string, appNode *yaml.Node, identities []age.Identity) error {
	for _, ref := range doc.ValueRefs() {
		if ref.Env != env || ref.App != app {
			continue
		}
		rel := ref.Path[4:]
		if yamlLookup(appNode, rel) != nil {
			continue
		}
		_, _, decryptable, err := editablePlaintext(ref.Raw, strings.Join(ref.Path, "."), identities)
		if err != nil {
			return err
		}
		if !decryptable {
			setYAMLPath(appNode, rel, yamlScalar(ref.Raw))
		}
	}
	return nil
}

func emptyYAMLMap() *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
}

func skeletonEnvNode() *yaml.Node {
	return &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
		Content: []*yaml.Node{
			yamlScalar("options"), emptyYAMLMap(),
			yamlScalar("apps"), emptyYAMLMap(),
		},
	}
}

func skeletonAppNode() *yaml.Node {
	return mapNode("values", emptyYAMLMap())
}

func cloneYAMLNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	clone := *node
	clone.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		clone.Content[i] = cloneYAMLNode(child)
	}
	return &clone
}

func yamlLookup(node *yaml.Node, path []string) *yaml.Node {
	cur := node
	for _, key := range path {
		if cur == nil || cur.Kind != yaml.MappingNode {
			return nil
		}
		cur = yamlMapValue(cur, key)
	}
	return cur
}

func yamlNodeString(node *yaml.Node) string {
	if node == nil {
		return ""
	}
	data, _ := yaml.Marshal(node)
	return string(data)
}

func emptyMapping(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.MappingNode && len(node.Content) == 0
}

func editedEnvNames(root *yaml.Node) []string {
	envs := yamlMapValue(root, "envs")
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

func encryptedValue(doc *config.Document, env string, path []string, recipientSet string, value string) (string, error) {
	set, err := doc.RecipientSetForWrite(path, env, recipientSet)
	if err != nil {
		return "", err
	}
	return encryptedValueWithSet(doc, set, value)
}

func encryptedEditedValue(doc *config.Document, env string, path []string, value string, envDefaultSet string) (string, error) {
	if enc, ok := doc.ExistingEncrypted(path); ok && enc.RecipientSet != "" {
		return encryptedValueWithSet(doc, enc.RecipientSet, value)
	}
	if envDefaultSet != "" {
		return encryptedValueWithSet(doc, envDefaultSet, value)
	}
	if set, ok := doc.GetScalar([]string{"cin", "defaults", "recipientSet"}); ok && set != "" {
		return encryptedValueWithSet(doc, set, value)
	}
	return "", errors.New("recipient set is required")
}

func encryptedValueWithSet(doc *config.Document, set string, value string) (string, error) {
	recipients, err := doc.Recipients(set)
	if err != nil {
		return "", err
	}
	kind := envelope.Scalar
	if strings.Contains(value, "{{") && strings.Contains(value, "}}") {
		kind = envelope.Template
	}
	payload, err := encodePayload(kind, value)
	if err != nil {
		return "", err
	}
	ciphertext, err := cryptoage.Encrypt(payload, recipients.Recipients)
	if err != nil {
		return "", err
	}
	return envelope.Format(envelope.EncryptedValue{
		Kind:         kind,
		Algorithm:    envelope.AlgorithmAgeV1,
		RecipientSet: set,
		Users:        recipients.Users,
		Ciphertext:   ciphertext,
	}), nil
}

func envDefaultRecipientSet(envNode *yaml.Node) string {
	defaults := yamlMapValue(envNode, "defaults")
	if defaults == nil || defaults.Kind != yaml.MappingNode {
		return ""
	}
	value := yamlMapValue(defaults, "recipientSet")
	if value == nil || value.Kind != yaml.ScalarNode {
		return ""
	}
	return value.Value
}

func validateEditedScope(doc *config.Document, filePath string, envs []string, app string, identities []age.Identity) error {
	schemas, err := cinschema.Discover(doc, filePath)
	if err != nil {
		return err
	}
	if len(schemas.LoadErrors) > 0 {
		return fmt.Errorf("schema file is invalid: %s: %v", schemas.LoadErrors[0].Path, schemas.LoadErrors[0].Err)
	}
	for _, env := range envs {
		if !doc.HasEnv(env) {
			continue
		}
		resolved, err := doc.ResolvedEnv(env)
		if err != nil {
			return err
		}
		apps := []string{app}
		if app == "" {
			apps = doc.AppNames(env)
		}
		for _, appName := range apps {
			if appName == "" {
				continue
			}
			if app == "" && appHasUndecryptableValue(doc, env, appName, identities) {
				continue
			}
			result, err := resolve.Env(resolved, appName, identities)
			if err != nil {
				return err
			}
			for _, key := range result.AppKeys() {
				if err := result.Resolve(resolve.CanonicalPath(appName, key)); err != nil {
					return err
				}
			}
			if errs := cinschema.ValidateResult(schemas, env, appName, result); len(errs) > 0 {
				return fmt.Errorf("schema validation failed: %s", errs[0].Err)
			}
		}
	}
	return nil
}

func appHasUndecryptableValue(doc *config.Document, env, app string, identities []age.Identity) bool {
	for _, ref := range doc.ValueRefs() {
		if ref.Env != env || ref.App != app {
			continue
		}
		_, _, decryptable, err := editablePlaintext(ref.Raw, strings.Join(ref.Path, "."), identities)
		if err != nil || !decryptable {
			return true
		}
	}
	return false
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

func mapNode(key string, value *yaml.Node) *yaml.Node {
	return &yaml.Node{
		Kind:    yaml.MappingNode,
		Tag:     "!!map",
		Content: []*yaml.Node{yamlScalar(key), value},
	}
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
	signal.Notify(signals, handledSignals()...)
	go func() {
		select {
		case sig := <-signals:
			_ = os.RemoveAll(path)
			signal.Stop(signals)
			signalSelf(sig)
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
	signal.Notify(signals, handledSignals()...)
	defer signal.Stop(signals)
	go func() {
		for {
			select {
			case sig := <-signals:
				_ = signalProcess(cmd.Process, sig)
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

type explainLayer struct {
	Env       string
	Path      []string
	FromLocal bool
}

func explainLayers(doc, localDoc *config.Document, env string, path []string) ([]explainLayer, error) {
	layers, err := collectExplainLayers(doc, env, path, false, nil)
	if err != nil {
		return nil, err
	}
	if localDoc == nil || !localDoc.HasEnv(env) {
		return layers, nil
	}
	localLayers, err := collectExplainLayers(localDoc, env, path, true, nil)
	if err != nil {
		return nil, err
	}
	return append(layers, localLayers...), nil
}

func collectExplainLayers(doc *config.Document, env string, path []string, fromLocal bool, stack []string) ([]explainLayer, error) {
	for i, name := range stack {
		if name == env {
			cycle := append(append([]string{}, stack[i:]...), env)
			return nil, fmt.Errorf("inheritance cycle detected: %s", strings.Join(cycle, " -> "))
		}
	}
	if !doc.HasEnv(env) {
		if len(stack) > 0 {
			return nil, fmt.Errorf("environment parent not found: %s", env)
		}
		return nil, fmt.Errorf("environment not found: %s", env)
	}

	var layers []explainLayer
	parents, err := doc.EnvExtends(env)
	if err != nil {
		return nil, fmt.Errorf("invalid extends for %s: %w", env, err)
	}
	for _, parent := range parents {
		parentLayers, err := collectExplainLayers(doc, parent, path, fromLocal, append(stack, env))
		if err != nil {
			return nil, err
		}
		layers = append(layers, parentLayers...)
	}
	if _, ok := doc.GetScalar(append([]string{"envs", env}, path...)); ok {
		layers = append(layers, explainLayer{
			Env:       env,
			Path:      append([]string(nil), path...),
			FromLocal: fromLocal,
		})
	}
	return layers, nil
}

func finalLayer(layers []explainLayer) (explainLayer, bool) {
	if len(layers) == 0 {
		return explainLayer{}, false
	}
	return layers[len(layers)-1], true
}

func (l explainLayer) displayPath() string {
	path := strings.Join(append([]string{"envs", l.Env}, l.Path...), ".")
	if l.FromLocal {
		return "local " + path
	}
	return path
}

func (l explainLayer) scope(selectedEnv string) string {
	if l.FromLocal {
		return "local override"
	}
	if l.Env == selectedEnv {
		return "selected env"
	}
	return "parent env"
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

func effectiveEnv(doc *config.Document, env string) string {
	if env != "" {
		return env
	}
	if defaultEnv := doc.DefaultEnv(); defaultEnv != "" {
		return defaultEnv
	}
	return "dev"
}

func targetPath(env, app, key string) ([]string, error) {
	if env == "" {
		return nil, errors.New("environment is required")
	}
	if app != "" {
		if strings.Contains(key, ".") {
			return nil, errors.New("app value key must not contain dots when using -a")
		}
		return []string{"envs", env, "apps", app, "values", key}, nil
	}
	parts := strings.Split(key, ".")
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("invalid path: %s", key)
		}
	}
	return append([]string{"envs", env}, parts...), nil
}

func secretPath(path []string) bool {
	if len(path) >= 4 && path[0] == "envs" && path[2] == "options" {
		return true
	}
	return len(path) == 6 && path[0] == "envs" && path[2] == "apps" && path[4] == "values"
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
