# cin

`cin` means config inject.

It is a CLI for storing encrypted app config in Git and injecting resolved
values into commands at runtime. Config values are encrypted with age. Plaintext
is not printed unless a command explicitly asks for it.

## Install

```bash
go build -o cin ./cmd/cin
```

Put the binary on your `PATH`.

## Quick Start

Create the shared config file at the repo root:

```bash
cin init vaishnav
```

Set root config for an environment:

```bash
cin set -e dev options.postgres.host postgres
cin set -e dev options.postgres.port 5432
cin set -e dev extends base
```

Read without leaking plaintext:

```bash
cin get -e dev options.postgres.host
```

Print plaintext only when needed:

```bash
cin get -e dev options.postgres.host --show
```

Edit the config in a secure temp file:

```bash
cin edit
```

Scope editing when you only want one environment or app:

```bash
cin edit -e dev
cin edit -e dev -a api
```

## App Values

App values are injected as environment variables.

```bash
cin set -e dev -a api DATABASE_URL 'postgres://{{ .options.postgres.host }}:{{ .options.postgres.port }}/api'
cin set -e dev apps.api.values.REDIS_URL redis://localhost:6379
cin run -e dev -a api -- pnpm dev
```

Export resolved app config:

```bash
cin export -e dev -a api --redact-values
cin export -e dev -a api --format json --stdout --yes
```

## Users

Users are age recipients. New users are pending until an active user approves
them and rekeys affected values.

```bash
cin users create alice
cin users list
cin users approve alice
```

Use `--age` when the public key is already known:

```bash
cin users create ci-prod --age age1...
```

Remove a user and rekey:

```bash
cin users remove alice
```

## Files

The default shared file is:

```text
configs.secret.yaml
```

If this file exists, it is loaded as a local override at highest precedence:

```text
configs.local.secret.yaml
```

Override or disable local config:

```bash
cin run --local-file path/to/local.secret.yaml -e dev -a api -- pnpm dev
cin run --no-local -e dev -a api -- pnpm dev
```

## Environment

`cin` reads `CIN_*` defaults from `.env` in the current directory and Git root
without overriding real process environment variables.

Useful variables:

```text
CIN_USER=vaishnav
CIN_AGE_KEY=AGE-SECRET-KEY-...
```

## Check Config

```bash
cin doctor
cin doctor -e dev -a api
cin explain -e dev -a api DATABASE_URL
```

## Command Groups

Project:

```text
cin init <username>
```

Config:

```text
cin set -e <env> [-a <app>] <key> [value]
cin get -e <env> [-a <app>] <key>
cin edit [-e <env>] [-a <app>]
cin explain -e <env> [-a <app>] <key>
```

Runtime:

```text
cin run -e <env> -a <app> -- <command>
cin export -e <env> -a <app>
```

Users:

```text
cin users create <username>
cin users list
cin users approve <username>
cin users remove <username>
```

Diagnostics:

```text
cin doctor
cin version
```
