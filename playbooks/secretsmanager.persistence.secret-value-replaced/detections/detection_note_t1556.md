# Detection Note — T1556 (Modify Authentication Process)

**Signal:** the value an application authenticates with being replaced by someone who should not be
replacing it.

## The rule cannot fire

It matches `eventName:"updatesecret"`. CloudTrail emits `UpdateSecret`. Eleventh instance of this
defect class across the source set.

## Three write paths, and the rule names the least used

| Call | Effect |
|---|---|
| `UpdateSecret` | New version, `AWSCURRENT` moves to it — what the rule watches |
| `PutSecretValue` | New version, `AWSCURRENT` moves to it — **what the SDKs and rotation Lambdas call** |
| `UpdateSecretVersionStage` | **Writes nothing.** `AWSCURRENT` moves to a version that already exists |

`UpdateSecretVersionStage` is the one worth the highest severity. It needs no permission to write the
secret and produces no write event, so an actor who once had a value staged can make it operative
again invisibly to any rule scoped to writes.

## Errors are excluded, so refusals are invisible

A denied write is an actor the permissions caught. The source rule filters it out; a document here
restores it, and the KQL separates a workload missing a grant (repeats against one secret) from abuse
(walks several).

## Response levers

**Old versions are retained, and that is the recovery.** Secrets Manager keeps 100 of the most recent
versions and all versions from the last 24 hours, so the value that was operative before is reachable
by `VersionId` — not only through `AWSPREVIOUS`, which is one deep. Recovery is a lookup, not a race.

**A version created long ago that now holds `AWSCURRENT`** means the label was moved rather than a
value written — that is the `UpdateSecretVersionStage` path, and it is the tell.

**`UpdateSecret` can change the KMS key too.** That changes who can decrypt the secret at rest while
the secret stays "encrypted", so a compliance check still passes.

**Consumers cache.** Moving `AWSCURRENT` back does not change what a running process holds until its
cache expires, which can be hours.

**MITRE:** the source maps `T1098` under TA0005. The technique is defensible; the tactic is not,
since nothing about the defender's visibility changes. `T1556 — Modify Authentication Process` is the
primary here — replacing a secret replaces the material an application authenticates with — and
`T1565.001 — Stored Data Manipulation` covers the purely destructive shape. Both verified live
2026-08-31.

**GuardDuty:** no finding type covers Secrets Manager value changes.

**Adjacent:** rotation being turned off — the other way to keep a value operative — is
`../../secretsmanager.persistence.rotation-disabled/`.

**Files here:**
- `sigma_t1556.yml` — four documents: `AWSCURRENT` moved to an existing version (high),
  `secretsmanager_secret_value_written` as the informational base rule, the refused case (medium),
  and a three-secrets-in-thirty-minutes correlation (high).
- `kql_t1556.kql` — separates the three paths, flags a KMS key change, and distinguishes a workload
  missing a grant from a walk across several secrets.

Full response procedure is in `../PLAYBOOK.md`.
