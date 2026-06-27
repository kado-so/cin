---
title: Config model
description: How cin stores users, encrypted values, environments, and apps.
---

`cin` keeps operational metadata readable and encrypts config values per key. Changing one value should keep unrelated Git diffs small.

## Files

```text
configs.secret.yaml
configs.local.secret.yaml
```

`configs.secret.yaml` is the shared Git-tracked file. `configs.local.secret.yaml` is machine-specific and ignored by Git.

## Shape

```yaml
cin:
  version: 1
  defaults:
    recipientSet: team
  users:
    vaishnav:
      age: age1...
      status: active
      approvedBy: [vaishnav]
  recipientSets:
    team:
      users: [vaishnav]

envs:
  dev:
    options:
      postgres:
        host: ENC[age-v1;set=team;data=...]
    apps:
      api:
        values:
          DATABASE_URL: ENC_TEMPLATE[age-v1;set=team;data=...]
```

## Resolution

Environments can extend other environments. App values can use encrypted templates, and templates resolve after the environment is merged.

```bash
cin explain -e dev -a api DATABASE_URL
```

Use `explain` when you need to see where a resolved value came from without dumping secret plaintext.
