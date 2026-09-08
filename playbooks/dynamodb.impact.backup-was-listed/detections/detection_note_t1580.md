# Detection Note — T1580 (Cloud Infrastructure Discovery)

**Signal:** a principal enumerating DynamoDB backups — and, in the correlations that matter,
deleting or restoring from one shortly afterwards.

**Enumeration alone is not a finding, and a rule that treats it as one gets muted.** `ListBackups`
is called by the console every time somebody opens the backups tab, by every backup-reporting job,
and by any recovery-point inventory. The source rule fires immediately, with no principal filter
and no grouping, on every one of those. It is rated P4, which is the only reason it has survived —
it lands somewhere nobody reads.

**What the original rule got wrong** — it alerts on the reconnaissance and never on what the
reconnaissance was for.

Two sequences give the enumeration meaning, and they mean opposite things:

- **`ListBackups` → `DeleteBackup`** — reconnaissance for destroying the recovery path. Backup
  deletion is immediate and there is no recycle bin, so by the time this is read the recovery point
  is gone.
- **`ListBackups` → `RestoreTableFromBackup` into a *different* table name** — reconnaissance for
  **copying the data out**. The original table is untouched, so no monitoring notices, no
  application breaks, and the copy carries every item. This is the shape most easily mistaken for
  a legitimate recovery, and the discriminator is one field: whether the target name differs from
  the source.

The corrected set keeps the enumeration as an informational base rule and puts the signal in two
ordered correlations over it.

## The third path the source rule cannot see at all

`UpdateContinuousBackups` disabling point-in-time recovery removes the recovery path without
touching a single backup object. There is no `DeleteBackup`, nothing enumerable disappears, and a
rule watching backups sees nothing. It is shipped here because a principal that enumerates, deletes
and *also* turns off PITR has removed both recovery mechanisms — which is the highest-severity
shape this service produces and needs no threshold.

## Response levers

**Deletion is immediate.** DynamoDB backups have no recycle bin and no recovery window, so the
response to `DeleteBackup` is never restoration of the backup — it is establishing what other
recovery point still exists. `../../dynamodb.impact.backup-was-deleted/` is the destruction playbook
and this one cross-references it rather than duplicating its procedure.

**A restore under a new name is a copy, and it is cheap to check.** `sourceTableName` and
`targetTableName` are both in the request. Where they differ, the original is intact and a full
copy of its contents now exists somewhere the original's access controls do not apply.

**Item-level operations are data events and are off by default.** So what was read *from* a
restored copy is not in CloudTrail unless a data-event trail exists, and `lookup-events` returns
zero for those calls whether or not they happened.

**MITRE:** the source carries `T1490 — Inhibit System Recovery`, which describes destroying the
recovery path rather than reading it. `T1580 — Cloud Infrastructure Discovery` covers the
enumeration; `T1490` is retained on the enumerate-then-delete correlation where it is correct; and
`T1530 — Data from Cloud Storage` on the enumerate-then-restore correlation, where the objective is
the data rather than its availability. All verified live 2026-08-30.

**Severity:** informational for the enumeration, critical for enumerate-then-delete with PITR
disabled, high for the other two correlations. The enumeration is deliberately not alertable.

**GuardDuty:** no coverage. There is no finding type whose resource is a DynamoDB backup, and the
`Discovery:IAMUser/AnomalousBehavior` family keys on unusual API patterns generally rather than on
this sequence.

**Files here:**
- `sigma_t1580.yml` — the enumeration base rule at informational, `DeleteBackup` and restore base
  rules, and the ordered correlations built over them.
- `kql_t1580.kql` — one row per principal per day with the three outcomes counted separately, and
  renamed restores called out explicitly as copies rather than recoveries.

Full response procedure is in `../PLAYBOOK.md`.
