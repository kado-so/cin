---
title: Quick start
description: Initialize cin, set encrypted values, and inject them into a command.
---

## Install

Install with Go:

```bash
go install github.com/kado-so/cin/cmd/cin@latest
```

You can also download a release from [GitHub Releases](https://github.com/kado-so/cin/releases).

## Create config

Create the shared encrypted config file at the repo root:

```bash
cin init vaishnav
```

This creates `configs.secret.yaml`.

## Add environment config

```bash
cin set -e dev options.postgres.host postgres
cin set -e dev options.postgres.port 5432
cin set -e dev extends base
```

Read a value without leaking plaintext:

```bash
cin get -e dev options.postgres.host
```

Print plaintext only when needed:

```bash
cin get -e dev options.postgres.host --show
```

## Inject app values

App values are injected as environment variables.

```bash
cin set -e dev -a api DATABASE_URL 'postgres://{{ .options.postgres.host }}:{{ .options.postgres.port }}/api'
cin set -e dev -a api REDIS_URL redis://localhost:6379
cin run -e dev -a api -- pnpm dev
```

## Local overrides

If `configs.local.secret.yaml` exists, `cin` loads it at highest precedence.

```bash
cin run --local-file path/to/local.secret.yaml -e dev -a api -- pnpm dev
cin run --no-local -e dev -a api -- pnpm dev
```
