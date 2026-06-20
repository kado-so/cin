# cin implementation design

`cin` means config inject. It is a serverless CLI for encrypted application
config and secret injection. It stores all configuration in Git as encrypted
YAML and injects resolved values into child processes at runtime. There is no
daemon, hosted vault, API server, or external control plane.

This document is the implementation contract for the first Go version.

## Product principles

- All app config values are secrets.
- All options are secrets.
- Templates are secrets because their structure can reveal infrastructure.
- Only operational metadata is plaintext.
- Secrets are injected at runtime, not written to disk.
- Plaintext is never printed unless explicitly requested.
- Encryption is per key, not whole-file.
- Changing one value should not rewrite unrelated encrypted values.
- Git diffs should be small and deterministic.
- CI/CD is modeled as a normal user/recipient.

## Non-goals

- No backend service.
- No hosted vault.
- No daemon.
- No remote API.
- No automatic stale-recipient detection requirement.
- No arbitrary code execution in templates.
- No plaintext local override files.

## User stories

### Local app development

Vaishnav wants to run the API locally with team defaults, but with a local
Postgres host and Redis URL.

```bash
cin set -e vaishnav options.postgres.host host.docker.internal
cin set -e vaishnav -a api REDIS_URL redis://localhost:6379
cin run -e vaishnav -a api -- pnpm dev
```

`envs.vaishnav` can extend `envs.dev`, which can extend shared envs.
Templates defined in parent envs are resolved after the child env is merged, so
the child option values affect parent templates.

### Shared dev config

The team wants a shared dev environment checked into Git.

```bash
cin set -e dev options.postgres.host postgres
cin set -e dev options.postgres.port 5432
cin set -e dev -a api DATABASE_URL 'postgres://{{ .options.postgres.user }}:{{ .options.postgres.password }}@{{ .options.postgres.host }}:{{ .options.postgres.port }}/api'
```

Because the value contains `{{` and `}}`, `cin set` stores it as an encrypted
template.

### Production deploy from CI

CI gets its own age identity and is approved like any other user.

```bash
cin users create ci-prod
cin users approve ci-prod
```

GitHub Actions:

```yaml
- name: Deploy API
  run: cin run -e prod -a api -- pnpm deploy
  env:
    CIN_USER: ci-prod
    CIN_AGE_KEY: ${{ secrets.CIN_AGE_KEY }}
```

### Safe onboarding

A new user is pending until an existing authorized user approves them.

```bash
cin users create alice
cin users approve alice
```

`cin users approve alice` is interactive. It shows the recipient sets that
include Alice and the values that will be rekeyed. The operator must type
`approve` exactly before `cin` rekeys those values.

### Plaintext leak prevention

By default:

```bash
cin get -e prod -a api DATABASE_URL
```

prints:

```text
DATABASE_URL = [secret]
```

Plaintext requires explicit intent:

```bash
cin get -e prod -a api DATABASE_URL --show
```

## File layout

The default shared config file is:

```text
configs.secret.yaml
```

The default local override file is:

```text
configs.local.secret.yaml
```

If `configs.local.secret.yaml` exists, it is loaded automatically and applied at
highest precedence. It can be replaced with:

```bash
cin run --local-file path/to/local.secret.yaml -e vaishnav -a api -- pnpm dev
```

It can be disabled with:

```bash
cin run --no-local -e vaishnav -a api -- pnpm dev
```

Local override files may only contribute `envs`. Any `cin` metadata, users,
recipient sets, or schemas in a local file are ignored. `cin doctor` warns when
non-env data appears in a local file.

## Recommended config schema

Author-facing YAML uses compact encrypted scalars:

```yaml
cin:
  version: 1

  defaults:
    recipientSet: team

  users:
    vaishnav:
      age: age1vaishnav...
      status: active
      approvedBy: [vaishnav]

    alice:
      age: age1alice...
      status: pending
      approvedBy: []

    ci-prod:
      age: age1ciprod...
      status: active
      approvedBy: [vaishnav]

  recipientSets:
    team:
      users: [vaishnav, alice]

    prod:
      users: [vaishnav, ci-prod]

  configSchemas:
    - "apps/*/cin.schema.yaml"
    - "services/*/config.schema.yaml"

envs:
  shared:
    defaults:
      recipientSet: team

    options:
      postgres:
        port: ENC[age-v1;set=team;users=vaishnav;data=...]
        user: ENC[age-v1;set=team;users=vaishnav;data=...]
        password: ENC[age-v1;set=team;users=vaishnav;data=...]

  dev:
    extends: shared
    defaults:
      recipientSet: team

    options:
      postgres:
        host: ENC[age-v1;set=team;users=vaishnav;data=...]

    apps:
      api:
        values:
          DATABASE_URL: ENC_TEMPLATE[age-v1;set=team;users=vaishnav;data=...]
          REDIS_URL: ENC[age-v1;set=team;users=vaishnav;data=...]

      worker:
        values:
          DATABASE_URL: ENC_TEMPLATE[age-v1;set=team;users=vaishnav;data=...]

  vaishnav:
    extends: dev
    options:
      postgres:
        host: ENC[age-v1;set=team;users=vaishnav;data=...]

    apps:
      api:
        values:
          REDIS_URL: ENC[age-v1;set=team;users=vaishnav;data=...]

  prod:
    extends: shared
    defaults:
      recipientSet: prod

    options:
      postgres:
        host: ENC[age-v1;set=prod;users=vaishnav,ci-prod;data=...]

    apps:
      api:
        values:
          DATABASE_URL: ENC[age-v1;set=prod;users=vaishnav,ci-prod;data=...]
```

### Top-level sections

`cin` contains only operational metadata:

- `version`
- `defaults`
- `users`
- `recipientSets`
- `configSchemas`
- future CLI metadata

`envs` contains all secret-bearing configuration:

- `defaults`
- `extends`
- `options`
- `apps.<app>.values`

There is no `userOverrides` section. Personal config is modeled as a normal env,
for example `envs.vaishnav`.

## Environment inheritance

`extends` is explicit. There is no special `base` env.

Valid forms:

```yaml
extends: dev
```

```yaml
extends: [shared, dev]
```

Rules:

- If `extends` is absent, the env inherits nothing.
- If `extends` is a string, merge that parent first, then the child.
- If `extends` is a list, merge parents left to right.
- The rightmost parent has highest parent precedence.
- The current env wins over all parents.
- Local override file data wins over shared file data.
- Missing parents are errors.
- Inheritance cycles are errors.

Example:

```yaml
envs:
  shared:
    options:
      postgres:
        port: ENC[...]

  dev:
    extends: shared
    options:
      postgres:
        host: ENC[...]

  vaishnav:
    extends: dev
    options:
      postgres:
        host: ENC[...]
```

Resolution for:

```bash
cin run -e vaishnav -a api -- pnpm dev
```

is:

```text
shared < dev < vaishnav < local vaishnav
```

### Merge semantics

- Maps are deep-merged.
- Scalars replace previous values.
- Encrypted values replace previous values.
- Encrypted templates replace previous values.
- Arrays replace previous values, not concatenate.
- `apps.<app>.values` is deep-merged by key.

## Encrypted scalar format

`cin` stores encrypted values in one-line compact scalars:

```text
ENC[age-v1;set=<recipientSet>;users=<sorted-users>;data=<base64url-age-ciphertext>]
ENC_TEMPLATE[age-v1;set=<recipientSet>;users=<sorted-users>;data=<base64url-age-ciphertext>]
```

Example:

```yaml
DATABASE_URL: ENC_TEMPLATE[age-v1;set=team;users=alice,vaishnav;data=...]
```

The serialized format should be deterministic:

- fields are ordered as `age-v1`, `set`, `users`, `data`
- users are sorted by username
- ciphertext is base64url without line wrapping
- no public keys are repeated inside encrypted value metadata

Internally, the parser normalizes this to a typed envelope:

```go
type EncryptedValue struct {
    Kind         EncryptedKind // scalar or template
    Algorithm    string        // age-v1
    RecipientSet string
    Users        []string
    Ciphertext   []byte
}
```

The public keys are stored once in `cin.users`.

## Encryption model

Each secret value is encrypted independently with age.

Plaintext payload before encryption is a typed JSON object:

```json
{
  "type": "string",
  "value": "postgres://..."
}
```

Template payload:

```json
{
  "type": "template",
  "value": "postgres://{{ .options.postgres.user }}:{{ .options.postgres.password }}@{{ .options.postgres.host }}:{{ .options.postgres.port }}/api"
}
```

Typed option payloads may store JSON-compatible values:

```json
{
  "type": "number",
  "value": 5432
}
```

`age` recipient public keys are looked up from:

```text
cin.recipientSets.<set>.users -> cin.users.<user>.age
```

### Identity discovery

Current `cin` user:

```text
1. --user
2. CIN_USER
3. error
```

Age private key discovery:

```text
1. CIN_AGE_KEY
2. CIN_AGE_KEY_FILE
3. ~/.config/cin/keys/<user>.txt
4. error
```

`cin` should not guess the current user by trying every key.

## Recipient set selection

When writing a value with `cin set`:

```text
if overwriting an existing encrypted value:
  preserve that value's recipientSet
else if envs.<env>.defaults.recipientSet exists:
  use that recipient set
else if cin.defaults.recipientSet exists:
  use that recipient set
else:
  error
```

The recipient set may be overridden explicitly:

```bash
cin set -e prod -a api DATABASE_URL --recipient-set prod --prompt
```

`cin doctor` should warn when an env extends a parent whose default recipient
set differs from the child. This is allowed, but it can surprise users when new
values are written.

## User lifecycle

### Create

```bash
cin users create alice
```

Behavior:

- Adds `cin.users.alice`.
- Generates or accepts an age public key.
- Sets status to `pending`.
- Does not rekey existing values.

Example metadata:

```yaml
alice:
  age: age1alice...
  status: pending
  approvedBy: []
```

### Approve

```bash
cin users approve alice
```

Behavior:

1. Verify current user is active.
2. Show the recipient sets that include Alice.
3. Show a redacted impact summary of values that will be rekeyed.
4. Require the operator to type `approve`.
5. Mark Alice active.
6. Add current user to `approvedBy`.
7. Rekey affected encrypted values.
8. Preserve unrelated encrypted values unchanged.

Approval is not cryptographic signing. `age` X25519 keys are encryption keys,
not signing keys. `approvedBy` is authorization and audit metadata.

Example prompt:

```text
Approving alice will grant access through these recipient sets:

  team
    users: alice, vaishnav
    values to rekey: 42

This will allow alice to decrypt values encrypted to those recipient sets.
Type approve to continue:
```

### List

```bash
cin users list
```

Shows users, status, age public key fingerprint, and recipient sets.

### Remove

```bash
cin users remove alice
```

Behavior:

- Remove Alice from recipient sets.
- Rekey affected values.
- Warn that already-pulled plaintext and Git history cannot be revoked.

Expected warning:

```text
warning: removing alice prevents future decryption after rekey
warning: this cannot revoke plaintext already copied locally or secrets present in Git history
fix: rotate affected secrets if alice may have accessed them
```

## Templates

Templates use Go-style delimiters but allow only variable lookup.

Example plaintext template before encryption:

```gotemplate
postgres://{{ .options.postgres.user }}:{{ .options.postgres.password }}@{{ .options.postgres.host }}:{{ .options.postgres.port }}/api
```

Template context uses lowercase map paths matching YAML:

```text
.options.postgres.host
.apps.api.values.REDIS_URL
.values.REDIS_URL
```

For a selected app, `.values` is an alias for:

```text
.apps.<selected-app>.values
```

### Template restrictions

- No functions.
- No pipelines.
- No conditionals.
- No ranges.
- No method calls.
- No arbitrary code execution.
- Missing references fail closed.
- Cycles fail closed.

Implementation should parse with Go's `text/template/parse` package and walk
the AST before execution. Only text nodes and simple field lookups are allowed.
Do not rely only on an empty `FuncMap`, because Go templates have predefined
global functions.

### Template detection

`cin set` auto-detects templates. If the provided value contains both `{{` and
`}}`, store it as `ENC_TEMPLATE[...]`; otherwise store it as `ENC[...]`.

There is no `set-template` command.

### Resolution order

For:

```bash
cin run -e vaishnav -a api -- pnpm dev
```

resolution is:

```text
1. Load shared config.
2. Load local override config if present and not disabled.
3. Resolve inheritance for selected env in shared config.
4. Resolve inheritance for selected env in local config, if present.
5. Merge shared resolved env with local resolved env.
6. Decrypt all required values.
7. Build template context from the final decrypted env graph.
8. Resolve templates.
9. Type-check resolved values using discovered schemas.
10. Inject selected app values into the child process environment.
```

If a template in a parent env references an option overridden by a child env, the
child value is used. Templates are resolved after inheritance and local overlay.

### Cycle detection

Template resolution builds a dependency graph. Cycles are errors.

Example error:

```text
error template cycle detected
path: values.API_URL -> values.BASE_URL -> values.API_URL
```

## CLI command semantics

### Global flags

Common flags:

```text
-f, --file <path>               default configs.secret.yaml
--local-file <path>             default configs.local.secret.yaml when present
--no-local                      disable local override file
--user <username>               current cin user
```

Current user can also come from:

```text
CIN_USER
```

Commands that resolve env data require:

```text
-e, --env <env>
```

`cin run` requires:

```text
-a, --app <app>
```

### Init

```bash
cin init <username> -f configs.secret.yaml
```

Creates:

- config file
- initial active user
- initial recipient set
- empty `envs`
- local age key if needed

### Set

`cin set` is the only config value write command.

Set an option:

```bash
cin set -e dev options.postgres.host postgres
cin set -e dev options.postgres.password --prompt
```

Writes:

```text
envs.dev.options.postgres.host
envs.dev.options.postgres.password
```

Set an app value:

```bash
cin set -e dev -a api DATABASE_URL 'postgres://{{ .options.postgres.user }}@{{ .options.postgres.host }}/api'
```

Writes:

```text
envs.dev.apps.api.values.DATABASE_URL
```

Rules:

- If path starts with `options.`, `-a` is not used.
- If `-a` is provided, key is written under app values.
- App value writes require `-a`.
- Values may be provided positionally.
- `--prompt` reads a value without echoing.
- `--stdin` reads from stdin.
- Values containing `{{` and `}}` are encrypted as templates.
- Other values are encrypted as scalar values.

### Get

```bash
cin get -e dev options.postgres.host
cin get -e dev -a api DATABASE_URL
```

Default output is redacted and machine-friendly:

```text
[secret]
```

Plaintext requires:

```bash
cin get -e dev -a api DATABASE_URL --show
```

With `--show`, `get` prints only the resolved value and a trailing newline. It
must not print the key name, source path, recipient set, provenance, or any other
metadata. Use `cin explain` for context.

### Run

```bash
cin run -e dev -a api -- pnpm dev
```

Behavior:

1. Resolve selected env.
2. Resolve selected app.
3. Decrypt needed options and app values.
4. Resolve templates.
5. Type-check against schemas.
6. Inject selected app values into environment variables.
7. Execute command.
8. Return child process exit code.

`run` requires `-a`. There is no "inject all apps" mode in MVP.

Secrets are passed as environment variables, not command-line arguments.

### Explain

```bash
cin explain -e dev -a api DATABASE_URL
```

Shows source and dependency graph without printing values:

```text
DATABASE_URL
  source: envs.dev.apps.api.values.DATABASE_URL
  kind: encrypted template
  recipientSet: team
  references:
    options.postgres.user      ok secret
    options.postgres.password  ok secret
    options.postgres.host      overridden by envs.vaishnav
    options.postgres.port      ok secret
  result: [secret]
```

### Export

```bash
cin export -e dev -a api --format dotenv --out .env
```

Rules:

- Requires `-a`.
- Writes plaintext only with explicit confirmation.
- `--yes` is required for non-interactive file export.
- `--yes` and an explicit stdout flag are required for stdout export.
- If neither `--out` nor the explicit stdout flag is provided, open the export in
  a local pager instead of writing plaintext into the terminal scrollback.
- `--redact-values` emits the resolved key set with `[secret]` values and does
  not require `--yes`.
- Temporary files use restrictive permissions.

### Users

```bash
cin users create <username>
cin users approve <username>
cin users list
cin users remove <username>
```

`approve` replaces the earlier `sign` terminology.

### Doctor

```bash
cin doctor
cin doctor -f configs.secret.yaml
cin doctor -e dev
cin doctor -e dev -a api
```

Doctor is a first-class feature and must produce actionable diagnostics.

## Schema discovery and type checking

Schema files are discovered through:

```yaml
cin:
  configSchemas:
    - "apps/*/cin.schema.yaml"
    - "services/*/config.schema.yaml"
```

The schema format should be JSON Schema-compatible YAML.

Recommended app schema:

```yaml
cinSchema:
  version: 1

app: api

values:
  type: object
  additionalProperties: false
  required:
    - DATABASE_URL
    - REDIS_URL
  properties:
    DATABASE_URL:
      type: string
      format: uri
    REDIS_URL:
      type: string
      format: uri
    SENTRY_DSN:
      type: string
```

Optional env-specific requirements:

```yaml
envs:
  prod:
    values:
      required:
        - SENTRY_DSN
```

Doctor and runtime should type-check resolved values against the schema for the
selected app. App values are ultimately injected as environment variables, but
the schema can validate their semantic type before conversion to string.

Examples:

- `type: string` injects the string.
- `type: number` validates numeric input and injects its canonical string form.
- `type: boolean` validates boolean input and injects `true` or `false`.
- `type: object` or `array` validates JSON-compatible values and injects compact
  JSON.

## Doctor diagnostics

Severity levels:

```text
error  blocks run/export
warn   suspicious but allowed
info   useful note
```

Categories:

- Recipients
- Users
- Encryption
- Env inheritance
- Local overrides
- Schemas
- Templates
- Values
- Runtime

### Required checks

Recipients and users:

- User is pending.
- Recipient set references unknown user.
- Active user is not present in any recipient set.
- Current user cannot decrypt values they are expected to access.
- Approval would grant access to a large or surprising set of values.

Encryption:

- App value is plaintext.
- Option value is plaintext.
- Template is plaintext.
- Encrypted scalar is malformed.
- Encrypted scalar references unknown recipient set.
- Encrypted scalar's user list does not match current recipient set.

Env inheritance:

- Missing parent env.
- Inheritance cycle.
- Parent default recipient set differs from child default recipient set.
- Local file includes ignored `cin` metadata.

Schemas:

- Schema glob matches no files.
- Schema file is invalid.
- Schema references unknown app.
- Required key is missing.
- Config key exists but schema does not declare it and `additionalProperties` is
  false.
- Key exists in one env but not another, unless schema allows it.
- Resolved value has wrong type.

Templates:

- Missing reference.
- Cycle.
- Disallowed template action.
- Template references an unknown app.
- Template references a value current user cannot decrypt.

Values:

- Selected env is missing.
- Selected app is missing.
- App value cannot be converted to env var string.

### Example output

```text
cin doctor

Users
  error alice is pending and cannot decrypt existing values
    fix: cin users approve alice

Recipients
  error recipient set prod references unknown user ci-prod
    fix: cin users create ci-prod

Schemas
  error apps/api/cin.schema.yaml requires REDIS_URL, but dev/api does not define it
    fix: cin set -e dev -a api REDIS_URL <value>

  warn STRIPE_SECRET_KEY exists in prod/api but is not declared by any schema
    fix: add it to the schema or remove it

Templates
  error dev/api/DATABASE_URL references options.postgres.port, but that option is missing
    fix: cin set -e dev options.postgres.port <value>

  error dev/api/API_URL has a template cycle
    path: values.API_URL -> values.BASE_URL -> values.API_URL

Local overrides
  warn configs.local.secret.yaml contains cin.users, which is ignored
    fix: move user metadata to configs.secret.yaml
```

## Safety rules

Hard rules:

- Do not print plaintext unless `--show` is passed.
- Do not log decrypted values.
- Redact values in `doctor`, `diff`, `explain`, errors, and logs.
- Do not pass secrets as child process command-line arguments.
- Inject secrets as child process environment variables.
- Exporting plaintext to a file requires confirmation or `--yes`.
- Temporary files must be created with mode `0600`.
- Temporary directories must be mode `0700`.
- Cleanup temporary files on normal exit, error, SIGINT, and SIGTERM.
- Avoid rewriting encrypted values that did not change.
- Use deterministic YAML serialization.
- Keep encrypted values one-line by default.
- Fail on plaintext app values and options.

## Error messages

Missing config:

```text
error config file not found: configs.secret.yaml
fix: run `cin init <username>` or pass `-f <file>`
```

Missing user:

```text
error current user is required
fix: pass --user <username> or set CIN_USER
```

Missing env:

```text
error environment not found: prod
available: dev, staging, vaishnav
```

Missing app:

```text
error app not found in env dev: api
available: worker, web
```

Missing app flag for run:

```text
error cin run requires -a <app>
fix: rerun with -a api
```

Cannot decrypt:

```text
error cannot decrypt dev/api/DATABASE_URL with current identity
fix: check CIN_AGE_KEY or ask an active user to run `cin users approve <username>`
```

Plaintext value:

```text
error dev/api/REDIS_URL is plaintext, but all app config values must be encrypted
fix: cin set -e dev -a api REDIS_URL <value>
```

Template missing reference:

```text
error dev/api/DATABASE_URL references missing value options.postgres.port
fix: cin set -e dev options.postgres.port <value>
```

Template disallowed action:

```text
error dev/api/DATABASE_URL uses unsupported template syntax
detail: only variable interpolation is allowed
```

Unsafe export:

```text
error refusing to write plaintext secrets to .env without confirmation
fix: rerun with --yes
```

## Go implementation architecture

Recommended package layout:

```text
cmd/cin/                 Cobra command wiring
internal/config/         YAML model, parser, serializer, merge
internal/envelope/       ENC[...] parser and formatter
internal/cryptoage/      age encryption/decryption and key discovery
internal/resolve/        env inheritance, local overlay, template resolution
internal/schema/         JSON Schema discovery and validation
internal/doctor/         diagnostics
internal/run/            env injection and process execution
internal/ui/             prompts, redaction, terminal output
internal/testutil/       fixtures and age test keys
```

Recommended libraries:

- `filippo.io/age` for encryption.
- `gopkg.in/yaml.v3` for YAML AST parsing and serialization.
- `github.com/spf13/cobra` for CLI commands.
- `github.com/santhosh-tekuri/jsonschema/v6` or equivalent for JSON Schema.
- `golang.org/x/term` for secret prompts.

YAML handling should preserve enough structure to avoid noisy diffs. If comment
preservation is too expensive in MVP, document that comments may be normalized.

## Test implementation plan

Tests are part of the product spec. The durable product-level coverage should
be written as behavioral stories first, with smaller unit, integration,
security, and golden tests added only where they support or protect those
stories.

### Package layout

Behavioral tests live in a separate package:

```text
internal/behavior/
```

Each behavioral story should live in its own test file. The file must start with
a short top comment explaining the user story, why it matters, and the main
future-regression invariant it protects.

Shared test harness code should live under `internal/behavior` or
`internal/testutil` if lower-level package tests need it too. Existing package
tests should stay next to the implementation when they test small invariants
such as envelope parsing, merge behavior, template validation, and recipient-set
selection.

Suggested behavioral story files:

```text
internal/behavior/local_developer_story_test.go
internal/behavior/shared_dev_templates_story_test.go
internal/behavior/ci_approval_story_test.go
internal/behavior/user_removal_story_test.go
internal/behavior/doctor_broken_repo_story_test.go
internal/behavior/export_safety_story_test.go
internal/behavior/explain_provenance_story_test.go
internal/behavior/edit_env_story_test.go
```

Example top comment:

```go
// Story: a local developer inherits the shared dev environment, overrides only
// their machine-specific options, and runs the API without writing plaintext.
//
// Protects: parent templates must resolve after local overrides, run must inject
// only the selected app values, and secret values must never be printed by cin.
```

### Behavioral harness

Behavioral tests should exercise the CLI entrypoint directly through exported
functions, not by shelling out to a compiled binary. This keeps tests fast while
still covering Cobra parsing, config files, real `age` encryption, schema
discovery, template resolution, user flows, local overrides, export behavior,
and safety guards.

The harness should look roughly like:

```go
type Story struct {
    Dir        string
    ConfigPath string
    LocalPath  string
    Home       string
}

func NewStory(t *testing.T) *Story
func (s *Story) Run(args ...string) Result
func (s *Story) RunAs(user string, args ...string) Result
func (s *Story) WriteSchema(app string, data string)
func (s *Story) ReadConfig() string
func (s *Story) AssertNoPlaintext(values ...string)
```

`Run` should call the CLI package function directly, such as `cli.Run(args,
stdout, stderr)`, with temp working directories and temp `HOME`. It should not
execute `cin` as a subprocess.

The harness should also provide focused helpers for common behavioral
assertions:

- Generate real age identities for named users.
- Set `CIN_USER`, `CIN_AGE_KEY`, `HOME`, `PWD`, and optional local `.env` files.
- Create app schema files under realistic `apps/<app>/cin.schema.yaml` paths.
- Read encrypted YAML back and assert structurally on scalar form.
- Assert sensitive values do not appear in stdout, stderr, YAML, explain,
  doctor, or redacted export output.
- Capture command execution without putting secrets in command-line arguments.
- Replace editor and pager seams during tests.

### Story coverage

Write these as behavior tests, one story per file:

- Local developer inherits shared `dev`, applies local overrides, and runs API
  with resolved injected env.
- Shared dev config uses encrypted options and templates to derive app values.
- CI is modeled as a normal user and can deploy only after approval.
- Pending users cannot decrypt until `users approve` rekeys affected values.
- Removed users cannot decrypt after rekey, with revocation warnings preserved.
- Parent templates resolve using child env and local override option values.
- `doctor` catches plaintext, schema mismatch, missing template refs, cycles,
  unsigned users, and decrypt-skip cases without leaking values.
- `export --redact-values` shows the resolved key set without plaintext.
- Plaintext export requires explicit `--stdout --yes` or `--out --yes`.
- `explain` shows dependency and override provenance without values.
- `get` returns one value only.
- `edit` allows whole-env editing without `-a`, preserves unavailable encrypted
  values, and only writes validated changes.

### Structural and golden assertions

Behavioral tests should use real generated age keys and real encrypted config
files. Golden assertions should be used for stable user-facing output such as
`doctor`, `explain`, `users list`, and `export --redact-values`. Encrypted YAML
should be checked structurally instead of golden-filed wholesale because `age`
ciphertext is randomized.

Structural encrypted-YAML assertions:

- Secret plaintext never appears in config files.
- Secret values are stored as compact `ENC[...]` or `ENC_TEMPLATE[...]` scalars.
- Unrelated encrypted scalars remain byte-identical after changing another key.
- Rekeying changes only values in affected recipient sets.
- Recipient metadata matches active recipient-set users.

Stable golden outputs to maintain:

- `cin init`
- `cin set` for a new option
- `cin set` for a new app value
- `cin set` overwriting an existing value
- `cin users approve`
- `cin users remove`
- `cin doctor`
- `cin explain`
- `cin users list`
- `cin export --redact-values`
- local override ignored-metadata warning

Golden tests must still assert that unrelated encrypted values are
byte-identical after mutation.

### Testing `cin edit`

`cin edit` should be tested as a behavioral story, but editor execution should
use a test seam rather than a real editor when possible.

Preferred seam:

```go
var runEditorCommand = runEditor
```

Production calls the real editor. Tests temporarily replace the seam:

```go
old := runEditorCommand
runEditorCommand = func(editor []string, path string, stdin io.Reader, stdout, stderr io.Writer) error {
    return os.WriteFile(path, editedYAML, 0o600)
}
t.Cleanup(func() { runEditorCommand = old })
```

This still exercises the real edit command flow: temp file creation, plaintext
edit document rendering, YAML parsing, unknown-key rejection, schema/template
validation, re-encryption, unchanged ciphertext preservation, and cleanup.

If the seam is not available yet, tests may set `$VISUAL` to a small fake editor
script that rewrites the provided temp path. That is closer to the real process
model but more platform-sensitive.

Edit behavior to cover:

- `cin edit` uses the default env and edits all decryptable env data.
- `cin edit -e dev` edits env-wide options and all app values.
- `cin edit -e dev -a api` edits the focused app plus referenced options.
- Undecryptable values are omitted and listed without plaintext.
- Unknown sections, unknown apps, and unknown keys fail without saving.
- Schema/template failures fail without saving.
- Unchanged encrypted values stay byte-identical.
- Temp dirs are `0700`, temp files are `0600`, and cleanup happens on success,
  error, and signal.

### Lower-level support tests

These tests belong next to the packages they exercise. They are not the primary
spec, but they make the story failures smaller and easier to diagnose.

Envelope parser:

- Parses `ENC[...]`.
- Parses `ENC_TEMPLATE[...]`.
- Rejects unknown algorithms.
- Rejects malformed fields.
- Sorts users deterministically.
- Serializes without public key repetition.

YAML:

- Loads valid config.
- Rejects plaintext option values.
- Rejects plaintext app values.
- Writes compact encrypted scalars.
- Preserves unrelated values on write.

Merge:

- Deep-merges maps.
- Replaces arrays.
- Replaces encrypted scalars.
- Merges app values by key.
- Applies rightmost parent precedence.
- Applies local file highest precedence.

Inheritance:

- Supports `extends: dev`.
- Supports `extends: [shared, dev]`.
- Errors on missing parent.
- Errors on cycle.

Templates:

- Resolves simple variable references.
- Uses child env overrides for parent templates.
- Fails on missing reference.
- Fails on cycles.
- Rejects functions.
- Rejects pipelines.
- Rejects `if`.
- Rejects `range`.

Recipient sets:

- Selects existing value recipient set on overwrite.
- Falls back to env default recipient set.
- Falls back to global default recipient set.
- Errors when no recipient set exists.

### Command integration coverage

Command-level tests should use real age keys generated in test fixtures. They
can share the behavioral harness when useful, but should stay focused on one
command path at a time.

- `cin init` creates usable config.
- `cin set` encrypts values.
- `cin get --show` decrypts values.
- `cin run` injects values into child process.
- `cin run` requires `-a`.
- Local override file changes resolved export output.
- `users create` creates pending user.
- `users approve` rekeys after typed approval.
- `users remove` rekeys and blocks removed user's key.
- `doctor` catches plaintext values.
- `doctor` catches schema mismatch.
- `doctor` catches template cycle.

### Security and leak coverage

- `get` redacts by default.
- `export --redact-values` redacts values.
- `doctor` never prints plaintext.
- `explain` never prints plaintext.
- `run` does not put secrets in command args.
- Export without `--yes` fails in non-interactive mode.
- Temp files are `0600`.
- Temp dirs are `0700`.
- Signal cleanup removes temp files.

## Known remaining work

- Add first-class recipient-set management commands instead of requiring manual
  YAML edits for non-default access groups.
- Make `cin edit` understand `--local-file` and `--no-local`, or document that
  edits always target the shared config file.
- Continue expanding `cin doctor` diagnostics and golden output coverage.
- Preserve comments and more of the original YAML style, if low-noise human diffs
  become more important than deterministic normalized output.
- Add no-op write detection so setting the same plaintext value can preserve the
  existing encrypted scalar.

## Open implementation notes

- Approval metadata is not a cryptographic signature. If cryptographic signing is
  needed later, add a separate signing key model.
- JSON Schema validation should run on resolved decrypted values, not encrypted
  envelopes.
- `cin doctor` can inspect encrypted metadata without decryption, but type and
  template checks require a working identity.
- The local override file is powerful because it has highest precedence. It must
  remain encrypted and should be gitignored by default.
- Avoid adding more write commands. `cin set` should remain the main mutation
  path unless a future workflow genuinely requires a separate command.
