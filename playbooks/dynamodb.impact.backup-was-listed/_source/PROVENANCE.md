# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Immediate rule over a query string, no threshold, no group-by |
| Scope captured | One alerting rule: Backup Was Listed |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

The source rule is `eventSource:"dynamodb.amazonaws.com" AND eventName:"listbackups"`, immediate,
ungrouped — so every row of the `Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is
auditable against the artifact.

**A read-only enumeration alerting on every occurrence is a rule that will be muted.** `ListBackups`
is called by the console every time somebody opens the backups tab, by every backup-reporting job,
and by any tool that inventories recovery points. Firing immediately, with no principal filter and
no grouping, guarantees volume from routine operation — and this is rated P4, so it lands in a
queue nobody reads, which is the only reason it has not already been switched off.

**What makes enumeration interesting is what follows it, not the enumeration.** `ListBackups`
before `DeleteBackup` is reconnaissance for destruction; `ListBackups` before
`RestoreTableFromBackup` into a new table name is reconnaissance for **copying** data out. The
corrected set keeps the enumeration as an informational base rule and puts the signal in two
ordered correlations over it.

**MITRE:** the source carries `T1490 — Inhibit System Recovery`, which describes destroying the
recovery path rather than reading it. Mapped here to `T1580 — Cloud Infrastructure Discovery` for
the enumeration itself, with `T1490` retained on the enumerate-then-delete correlation, where it is
correct, and `T1530 — Data from Cloud Storage` on the enumerate-then-restore correlation. All
verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. The `DeleteBackup` and restore
rules here are correlation components, not separate use cases; `../../dynamodb.impact.backup-was-deleted/`
is the destruction use case and cross-references this one.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth is inline in the shipped files.
