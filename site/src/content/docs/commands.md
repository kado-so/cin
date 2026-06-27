---
title: Commands
description: cin command reference.
---

## Project

```text
cin init <username>
```

## Config

```text
cin set -e <env> [-a <app>] <key> [value]
cin get -e <env> [-a <app>] <key>
cin edit [-e <env>] [-a <app>]
cin explain -e <env> [-a <app>] <key>
```

## Runtime

```text
cin run -e <env> -a <app> -- <command>
cin export -e <env> -a <app>
```

Useful export forms:

```bash
cin export -e dev -a api --redact-values
cin export -e dev -a api --format json --stdout --yes
```

## Users

Users are age recipients. New users are pending until an active user approves them and rekeys affected values.

```text
cin users create <username>
cin users list
cin users approve <username>
cin users remove <username>
```

Use an existing public key:

```bash
cin users create ci-prod --age age1...
```

## Diagnostics

```text
cin doctor
cin doctor -e <env> -a <app>
cin version
```
