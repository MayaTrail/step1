# IR Playbook: DynamoDB Deletion Protection Disabled — Removing the Guard on an Unrecoverable Operation via `dynamodb:UpdateTable`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defensive control removal / pre-destruction staging (the one property that stops a table being destroyed is switched off, leaving `DeleteTable` unguarded) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** for the disable alone, **Critical** once a `DeleteTable` follows it. Deletion protection exists precisely because the operation it guards cannot be undone — AWS: *"Deleting a table is an unrecoverable operation."* A table that carried protection is by definition one someone judged worth protecting, so removing it is a deliberate act against that decision. The source rates it **P3**, which triages a precondition for irreversible data loss alongside a routine configuration change |
| MITRE Tactics | Stealth (TA0005), Impact (TA0040) |
| MITRE Techniques | T1685 (primary), T1485 (secondary) — both verified live 2026-08-29 |
| Services in Scope | DynamoDB, CloudTrail (management), CloudWatch (`AWS/DynamoDB`), IAM, Organizations (SCP), AWS Backup, and every application that reads or writes the affected table |

**What the technique does:** the actor calls `dynamodb:UpdateTable` with `DeletionProtectionEnabled: false`
against a table that had protection on. Nothing moves, nothing becomes readable, no alarm in
the application fires — the table keeps serving traffic unchanged. What changed is that the
property AWS describes as making a table so that "it cannot be deleted by anyone" is gone, and
`DeleteTable` will now succeed for any principal holding that permission. The actor then calls
`DeleteTable`. The table goes to `DELETING`, its indexes go with it, any stream on it goes
`DISABLED` and is auto-deleted after 24 hours, and when the operation concludes "the table no
longer exists in DynamoDB". If point-in-time recovery was on, DynamoDB leaves behind a single
system snapshot named `<table>$DeletedTableBackup`, retained 35 days. If it was not, and no
on-demand backup exists, the data is gone.

**Detection thesis.** The discriminator is **`requestParameters.deletionProtectionEnabled`**,
because `DeletionProtectionEnabled` is an optional Boolean *parameter* of `UpdateTable` and not
an API of its own — the same event name is emitted for a capacity change, a billing-mode
switch, an index create, a Streams toggle, an SSE key swap and a replica add. The source rule
does read that parameter, which is more than its siblings manage; what it fails to capture is
that the parameter is a **JSON boolean** and it compares against the quoted string `"false"`,
and that the disable is a precondition rather than an incident — nothing joins it to the
`DeleteTable` it was preparing for.

> The destruction this enables is `../dynamodb.impact.multiple-tables-deleted/`. The
> `UpdateTable` calls this rule does *not* match — capacity, encryption, Streams, replicas —
> are `../dynamodb.defense-evasion.table-configuration-modified/`. The other way to make a
> deletion unrecoverable is to remove the recovery point:
> `../dynamodb.impact.backup-was-deleted/`.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail multi-region trail capturing DynamoDB **management** events. `UpdateTable`,
  `DeleteTable`, `CreateTable`, `CreateBackup`, `DeleteBackup`, `ListBackups`,
  `RestoreTableFromBackup` and `RestoreTableToPointInTime` are all logged **by default** —
  AWS's DynamoDB CloudTrail page enumerates them as control-plane events. `UpdateContinuousBackups`,
  which is how PITR is turned off, is **absent from that enumerated list** even though
  `DescribeContinuousBackups` is present. Treat its presence in your trail as **unverified
  against primary documentation** and confirm empirically before building an alert on it
- **Field shape, verified against AWS's published log examples.** `UpdateTable`'s example
  carries **no `tableName` in `requestParameters`** — the table appears only at
  `responseElements.tableDescription.tableName`, nested under a wrapper object matching the
  API's `TableDescription` response element. `DeleteTable` *does* carry
  `requestParameters.tableName`, and returns `responseElements.tableDescription` with
  `itemCount` and `tableSizeBytes`, which is the size of the loss recorded in the event itself.
  `itemCount` is an approximate figure DynamoDB refreshes periodically, not a live count
- **`tableName` may be a bare name or a full table ARN.** The API documents "You can also
  provide the Amazon Resource Name (ARN) of the table in this parameter" and caps the field at
  1024 characters for that reason. An equality test against a bare name silently drops every
  ARN-form call
- A current inventory of which tables carry `DeletionProtectionEnabled: true`, refreshed by
  `DescribeTable`. Protection is **off by default** — including on global replicas and on
  tables restored from backups — so this rule's population is only the tables someone
  deliberately protected, and its silence is not an all-clear
- A current inventory of which tables have PITR enabled (`DescribeContinuousBackups`) and
  which have on-demand backups (`ListBackups`, **backup type `ALL`** — the default is `USER`
  and hides the `$DeletedTableBackup` system snapshots). This is what decides whether a
  deletion is recoverable, and it must exist *before* the deletion
- A baseline of which principals own table lifecycle — in most accounts one deployment role
  and one break-glass role

**Alerting (must be pre-configured)**
- **`UpdateTable` setting `deletionProtectionEnabled` to false, succeeding, by a principal outside the table-lifecycle allowlist → P0**
- **A protection disable followed by a `DeleteTable` from the same principal within 24 hours → P0**
- **`DeleteTable` succeeding on a table with neither PITR enabled nor any on-demand backup → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `UpdateTable` setting `deletionProtectionEnabled` to false, succeeding, by a principal outside the table-lifecycle allowlist | CloudTrail (management) | T1685 |
| P0 | A protection disable followed by a `DeleteTable` from the same principal within 24 hours | CloudTrail (management) | T1485 |
| P1 | `DeleteTable` succeeding on a table with neither PITR enabled nor any on-demand backup | CloudTrail (management) + `DescribeContinuousBackups` | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `UpdateTable` denied repeatedly across tables (`AccessDeniedException` / `NotAuthorized`) — boundary mapping, not a change | CloudTrail (management) | T1685 |
| P2 | `UpdateContinuousBackups` disabling PITR, or reducing `RecoveryPeriodInDays` — see the caveat on its logging in §1 | CloudTrail (management) | T1490 |
| P3 | A table created without `deletionProtectionEnabled` where the tag set marks it production — protection is off by default, so this is the silent majority | CloudTrail (management) | T1685 |

### Detection Rule Quality Notes

The source rule inspects the right field and then gets the type wrong, stops at the
precondition, and never asks who called.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Compares `requestParameters.deletionProtectionEnabled` against the quoted string `"false"` | The parameter is documented `Type: Boolean`, so CloudTrail carries a JSON boolean. Harmless in a dialect that stringifies at index time; **silently matches nothing** the moment the logic is reimplemented in `jq`, in a JSON-typed Sigma backend, or in any platform migration — a P3 rule that quietly becomes a rule that never fires | Compare against a boolean; in KQL use `tobool()`, which accepts both forms |
| No principal check | Fires identically for the deployment pipeline decommissioning a table on a change ticket and for a compromised session staging a destruction. In an account where table lifecycle belongs to a pipeline, the caller is most of the signal and it is unused | Allowlist the table-lifecycle roles; alert on everyone else |
| Nothing joins the disable to the deletion it enables | The two events arrive as unrelated P3s, hours apart, and the destruction is triaged as an isolated `DeleteTable` with no visible motive. The sequence is the incident; neither half alone is | Ship the `temporal_ordered` correlation — `critical` on disable-then-delete by one principal inside 24 hours |
| P3 priority | A precondition for an operation AWS calls "unrecoverable" is triaged alongside a capacity change | P0 for a non-pipeline disable; `critical` for the pair |
| Silence is presented as safety | Deletion protection is **off by default**, "including global replicas, and tables restored from backups", so the rule can only ever fire for tables that were explicitly protected. Most exposed tables never produce an event at all | Pair the rule with a periodic `DescribeTable` sweep of current protection state — §5's assertion |

**Recommended detection — an UpdateTable call that turns deletion protection off.**

```yaml
# DynamoDB Deletion Protection Disabled (T1685 / T1485)
#
# THE EVENT NAME IS NOT THE SIGNAL. `DeletionProtectionEnabled` is an optional Boolean
# *parameter* of `UpdateTable`, not an API of its own (verified against the DynamoDB API
# Reference for UpdateTable, 2026-08-29). The same `UpdateTable` event name is emitted for a
# capacity change, a billing-mode switch, a global secondary index create or delete, a
# Streams enable, an SSE key swap and a cross-Region replica add. A rule that matches
# `eventName: UpdateTable` therefore fires on every autoscaling adjustment in the account.
# The single field `requestParameters.deletionProtectionEnabled` is the entire discriminator,
# and the source rule does inspect it — which is more than most of its siblings do.
#
# TYPE TRAP. The parameter is documented as `Type: Boolean`, so CloudTrail carries a JSON
# boolean `false`, not the string "false". A reimplementation that compares against a quoted
# "false" in jq matches nothing while looking correct. The rule below uses a YAML boolean.
#
# WHY THIS IS A PRECONDITION, NOT AN OUTCOME. Deletion protection is OFF BY DEFAULT for
# every table, "including global replicas, and tables restored from backups" (DynamoDB
# Developer Guide, Using deletion protection). So the population of tables this rule can ever
# fire for is only those where someone deliberately turned it ON. Its silence is not evidence
# that no table is exposed. Turning it off changes nothing by itself: the damage is the
# `DeleteTable` that follows, and "Deleting a table is an unrecoverable operation" unless
# point-in-time recovery or an on-demand backup exists. The temporal correlation below is the
# rule that actually names the incident.
#
# FIELD SHAPE. AWS's own published `UpdateTable` CloudTrail example carries NO `tableName` in
# `requestParameters` — the table is named only at
# `responseElements.tableDescription.tableName` (nested under a wrapper object, matching the
# API's `TableDescription` response element). `DeleteTable` does carry
# `requestParameters.tableName`, and also returns `responseElements.tableDescription` with
# `itemCount` and `tableSizeBytes`. Any join between the two events must tolerate the missing
# request-side name, which is why the correlation groups by principal and not by table.
title: DynamoDB deletion protection disabled on a table
id: 3f1c0f4a-6d2b-4a0e-9a3c-7b5e2d1f8c40
name: dynamodb_deletion_protection_disabled
status: experimental
description: >-
  An UpdateTable call set DeletionProtectionEnabled to false, removing the only control that
  prevents a table from being destroyed by anyone holding dynamodb:DeleteTable. Deletion
  protection is off by default, so a table that had it on was deliberately protected, and
  turning it off is a deliberate act against that decision.
references:
  - https://attack.mitre.org/techniques/T1685/  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.Basics.html  # retrieved 2026-08-29
tags:
  - attack.stealth
  - attack.t1685
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'UpdateTable'
  # Documented Type: Boolean. A quoted 'false' here matches nothing on a JSON-typed backend.
  protection_off:
    requestParameters.deletionProtectionEnabled: false
  success:
    errorCode: null
  condition: selection and protection_off and success
falsepositives:
  - >-
    A planned decommission, where the table is intentionally unprotected and then deleted by
    the pipeline that owns it. Distinguishable by principal and by a change record; if it is
    frequent, the finding is that decommissions are not going through change control.
level: high
---
# Base rule — sequence component only, not for direct alerting. Carries the success filter so
# a DeleteTable that was DENIED cannot compose into the critical correlation below (D-f): a
# refused deletion is boundary mapping, not destruction.
title: DynamoDB table deleted
id: 8c73a1de-4b90-42f7-8d1a-0e6c9f2b4a51
name: dynamodb_table_deleted_bb
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DeleteTable.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'DeleteTable'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# THE RULE THAT NAMES THE INCIDENT. Disabling protection is preparation; deleting the table
# is the act. Ordered, because the reverse sequence is meaningless — a table already deleted
# cannot have its protection disabled.
#
# Timespan basis: 24h, not minutes. There is no documented cooldown between UpdateTable and
# DeleteTable to anchor a short window on, and the two halves are frequently separated by a
# deliberate pause — the disable is cheap, reversible and unalarming on its own, so an actor
# with any patience separates them. A 24-hour span costs nothing in false positives because
# BOTH halves are already rare: the disable can only fire on tables that were explicitly
# protected, and the delete half is success-filtered. Shorten it only if your own change
# windows justify it.
#
# Grouped by principal, NOT by table: AWS's published UpdateTable example carries no
# `tableName` in requestParameters, so the two events cannot be reliably joined on the table.
# The analyst confirms the table match from the response side; kql_t1685.kql does that join.
title: DynamoDB deletion protection disabled and a table then deleted by the same principal
id: b0d5e937-2a48-4c16-bf3e-91a7c4e08d62
status: experimental
description: >-
  One principal removed deletion protection and then deleted a table. If the tables match,
  the protection was removed in order to destroy that table, and the data is gone unless
  point-in-time recovery or an on-demand backup existed at the moment of deletion.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: temporal_ordered
  rules:
    - dynamodb_deletion_protection_disabled
    - dynamodb_table_deleted_bb
  group-by:
    - userIdentity.arn
  timespan: 24h
level: critical
```

The rule cannot tell you whether the table is *recoverable*, because nothing about PITR or
backups is in the `UpdateTable` event — that requires `DescribeContinuousBackups` and
`ListBackups`, which Query 2 runs. It also cannot join the disable to the deletion on the table
name, because AWS's published `UpdateTable` example carries no `tableName` in
`requestParameters`; the Sigma correlation therefore groups by principal, and
`detections/kql_t1685.kql` does the join properly on the normalised name.

---

### Key Investigation Queries

> DynamoDB is regional and so is every table — run these in the table's region, and repeat per region if the actor moved between them. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` for busy windows.

#### Query 1 — Reconstruct: who disabled protection, on what, and what they deleted afterwards

```bash
REGION="us-east-1"
RAW=$(for EV in UpdateTable DeleteTable; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all: failed call, wrong region,"
  echo "    or missing cloudtrail:LookupEvents. This is NOT 'no table was unprotected'."
else
  # UpdateTable's published example carries NO tableName in requestParameters - the table is
  # named only in responseElements.tableDescription.tableName. DeleteTable carries it in the
  # request AND returns itemCount/tableSizeBytes. Both are reduced to a bare table_name so the
  # two halves can be compared; tableName may legally be a full ARN, hence the split.
  echo "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "dynamodb.amazonaws.com") |
    (.requestParameters.tableName // .responseElements.tableDescription.tableName // "")
      as $raw |
    {time: .eventTime, event: .eventName, caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     table_name: ($raw | split("/") | last),
     protection_change: (.requestParameters.deletionProtectionEnabled // "not-in-this-call"),
     items_lost: (.responseElements.tableDescription.itemCount // null),
     bytes_lost: (.responseElements.tableDescription.tableSizeBytes // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress, agent: .userAgent}' |
  jq -s 'sort_by(.time)'
fi
```

Read it as a sequence, not as a list. `protection_change` is `false` only on the calls that
actually disabled protection; every other `UpdateTable` shows `not-in-this-call` and is a
capacity, index, encryption or replica change belonging to
`../dynamodb.defense-evasion.table-configuration-modified/`. A `false` followed by a
`DeleteTable` on the same `table_name` from the same `caller_arn` is the incident, and
`items_lost` and `bytes_lost` on that deletion are the size of the loss — approximate, because
`itemCount` is refreshed periodically rather than live. Count `error` values separately from
successes: repeated `AccessDeniedException` or `NotAuthorized` across tables is boundary
mapping, not a change. Record `table_name`, `caller_arn` and `access_key` as IOCs.

#### Query 2 — Inspect: for every table the actor touched, is it still protected and is it still recoverable

```bash
REGION="us-east-1"
TARGET_TABLES="<table-names-from-Query-1>"
for T in $TARGET_TABLES; do
  DESC=$(aws dynamodb describe-table --table-name "$T" --region "$REGION" --output json)
  CB=$(aws dynamodb describe-continuous-backups --table-name "$T" --region "$REGION" --output json)
  # backup-type ALL is required: the default is USER and hides the SYSTEM snapshots, including
  # the <table>$DeletedTableBackup that a PITR-enabled deletion leaves behind.
  BK=$(aws dynamodb list-backups --table-name "$T" --backup-type ALL --region "$REGION" --output json)
  if [ -z "$DESC" ]; then
    echo "[!] $T - describe-table returned nothing. Either the table is GONE or the call"
    echo "    failed. Check list-backups output below before concluding either way."
  else
    printf '%s' "$DESC" | jq -r --arg t "$T" '.Table |
      "\($t): status=\(.TableStatus) protection=\(.DeletionProtectionEnabled // "absent") items=\(.ItemCount) bytes=\(.TableSizeBytes)"'
  fi
  if [ -z "$CB" ]; then
    echo "    [!] describe-continuous-backups failed - PITR state UNKNOWN, not disabled"
  else
    printf '%s' "$CB" | jq -r '.ContinuousBackupsDescription.PointInTimeRecoveryDescription |
      "    pitr=\(.PointInTimeRecoveryStatus) window_days=\(.RecoveryPeriodInDays // "n/a") earliest=\(.EarliestRestorableDateTime // "n/a")"'
  fi
  if [ -z "$BK" ]; then
    echo "    [!] list-backups failed - recovery points UNKNOWN, not zero"
  else
    printf '%s' "$BK" | jq -r '.BackupSummaries as $b | if ($b | length) == 0
      then "    backups=NONE"
      else "    backups=\($b | length): " + ($b | map(.BackupName + "(" + .BackupType + ")") | join(", ")) end'
  fi
done
```

`protection=false` or `protection=absent` means the table is deletable by anyone holding
`dynamodb:DeleteTable` right now — `absent` is the default state and is just as exposed as an
explicit `false`. `pitr=DISABLED` together with `backups=NONE` is the worst cell in the grid:
that table's deletion would be final, and it is the one to re-protect first. A `BackupType` of
`SYSTEM` with a name ending `$DeletedTableBackup` means the table has **already been deleted**
and this snapshot — retained 35 days from the deletion — is the only thing left of it. Every
`[!]` here is an unknown that must be written into the incident record as unknown; none of them
is a clean result.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="DeleteTable UpdateTable"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "dynamodb.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Grouped by caller rather than by resource,
because the question eradication needs answered is *how much of this is one actor's work* — a
per-resource list cannot say. `access_key` is emitted because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` whether or not it happened; the preamble's caveat applies.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN: one credential is used across many sessions, and
the key identifies the credential. The per-service grouping answers what this playbook cannot —
whether this technique was the objective or one stop on a tour. A service in that list with no
business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID, so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Re-protect before you contain. Deletion protection is a property of the table and takes effect
immediately, whereas containing the principal takes several API calls and a session revocation
that does not stop a credential the actor re-fetches — so closing the window on the table is
both faster and more certain than closing it on the identity. If the table is already gone,
skip Step 1 and go straight to Step 2, then to §5 to establish what survived.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Re-enable deletion protection, and prove it took

```bash
REGION="us-east-1"
TARGET_TABLES="<table-names-from-Query-1>"
for T in $TARGET_TABLES; do
  # UpdateTable is asynchronous: the table goes ACTIVE -> UPDATING and the call returns
  # immediately. The read-back below is what proves the change landed, not the call's exit code.
  OUT=$(aws dynamodb update-table --table-name "$T" --deletion-protection-enabled \
          --region "$REGION" --output json 2>&1)
  case "$OUT" in
    *ResourceNotFoundException*)
      echo "[!] $T does not exist - it was already deleted, or the region is wrong."
      echo "    Do not treat this as protected. Go to §5 and establish what survived.";;
    *ResourceInUseException*)
      echo "[!] $T is mid-update; DynamoDB rejects a second UpdateTable while UPDATING."
      echo "    Retry in a minute - the table is NOT yet protected.";;
    *tableDescription*|*TableDescription*)
      echo "[i] $T - update-table accepted, verifying...";;
    *)
      echo "[!] INCONCLUSIVE - unexpected update-table output for $T: $OUT";;
  esac
  STATE=$(aws dynamodb describe-table --table-name "$T" --region "$REGION" \
            --query 'Table.DeletionProtectionEnabled' --output text)
  if [ -z "$STATE" ]; then
    echo "[!] $T - could not read protection state back. UNKNOWN, not protected."
  elif [ "$STATE" = "True" ] || [ "$STATE" = "true" ]; then
    echo "[OK] $T is protected against deletion"
  else
    echo "[FAIL] $T reports DeletionProtectionEnabled=$STATE - still deletable"
  fi
done
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["dynamodb:DeleteTable","dynamodb:UpdateTable","dynamodb:DeleteBackup","dynamodb:UpdateContinuousBackups"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name is the LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyDdbDestroy" --policy-document "$DENY"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name is the 2ND segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyDdbDestroy" --policy-document "$DENY"
  echo "[OK] revoked pre-$CUTOFF sessions and denied DynamoDB destruction for role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
  echo "    service principal. Contain manually; neither branch above applies."
fi
```

The session-revocation policy denies only tokens issued **before** `$CUTOFF`. A credential the
actor re-fetches after this runs gets a newer `aws:TokenIssueTime` and is not covered — it
kills the leaked session, it does not gate the role. The `EmergencyDenyDdbDestroy` statement is
what actually holds the line, and it deliberately denies `dynamodb:UpdateTable` outright, which
**will break autoscaling on every table this principal manages**. That is acceptable for the
duration of the incident and is the reason §4 removes it explicitly.

---

## 4. Eradication

### Remove Attacker Access

- **Re-protect every table the principal touched, not just the one that alerted.** Query 1's
  full event list is the work-list; a single alert is one row of it.
- **Restore the recovery posture the disable was aimed at.** If PITR was also turned off, turn
  it back on — and note that re-enabling PITR starts a **new** recovery window from that
  moment. The days between the disable and the re-enable are not recoverable and never will be.
- **Hunt the rest of the session.** Pull every DynamoDB call by the same `access_key` from
  Query 1's window: a principal that disabled deletion protection is a principal whose other
  activity matters. `DeleteBackup` in the same session is
  `../dynamodb.impact.backup-was-deleted/`; `RestoreTableFromBackup` to another region is a
  data copy and belongs to `../dynamodb.impact.multiple-tables-created/`.
- **Right-size the permission.** `dynamodb:DeleteTable` is needed by no workload at runtime;
  only whatever owns table lifecycle needs it. `dynamodb:UpdateTable` cannot be removed as
  cleanly — autoscaling and every capacity change require it — which is exactly why the
  guardrail in §6 constrains the *deletion* rather than the update.
- **Remove the emergency policies once clean, and assert it** — both branches, because §3 could
  have taken either. Leaving `EmergencyDenyDdbDestroy` in place is not a safe default: it
  denies `UpdateTable`, so autoscaling stays broken and the next capacity event throttles
  production.

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}'); K=role
  for P in EmergencyDenyDdbDestroy EmergencyRevokeSessions; do
    aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
  LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text)
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}'); K=user
  aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyDdbDestroy"
  LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text)
else K=none; LEFT=""; fi
case "$K:$LEFT" in
  none:*)      echo "[!] INCONCLUSIVE - neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify every affected table is both protected and recoverable

```bash
REGION="us-east-1"
TARGET_TABLES="<table-names-from-Query-1>"
BAD=0; UNKNOWN=0
for T in $TARGET_TABLES; do
  PROT=$(aws dynamodb describe-table --table-name "$T" --region "$REGION" \
           --query 'Table.DeletionProtectionEnabled' --output text)
  PITR=$(aws dynamodb describe-continuous-backups --table-name "$T" --region "$REGION" \
           --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' \
           --output text)
  BKJSON=$(aws dynamodb list-backups --table-name "$T" --backup-type ALL --region "$REGION" --output json)
  # An empty capture is a call that did not run, never "zero backups": list-backups always
  # returns a BackupSummaries array, so no output at all means the call failed.
  if [ -z "$BKJSON" ]; then NBK=""; else NBK=$(printf '%s' "$BKJSON" | jq '.BackupSummaries | length'); fi
  if [ -z "$PROT" ] || [ -z "$PITR" ] || [ -z "$NBK" ]; then
    echo "[!] $T INCONCLUSIVE - protection='$PROT' pitr='$PITR' backups='$NBK'."
    echo "    A blank field is a call that failed, not a clean result. Do not close on this."
    UNKNOWN=$((UNKNOWN+1))
  elif [ "$PROT" != "True" ] && [ "$PROT" != "true" ]; then
    echo "[FAIL] $T is NOT protected against deletion (DeletionProtectionEnabled=$PROT)"
    BAD=$((BAD+1))
  elif [ "$PITR" != "ENABLED" ] && [ "$NBK" -eq 0 ]; then
    echo "[FAIL] $T is protected but has NO recovery point at all - PITR $PITR, 0 backups."
    echo "       Protection stops deletion; it does not survive one. Enable PITR."
    BAD=$((BAD+1))
  else
    echo "[OK] $T protected, PITR=$PITR, recovery points=$NBK"
  fi
done
echo "--- $BAD failing, $UNKNOWN inconclusive ---"
[ "$BAD" -eq 0 ] && [ "$UNKNOWN" -eq 0 ] && echo "[OK] every affected table is protected and recoverable" \
                                         || echo "[FAIL] do not close this incident"
```

Every branch is reachable after the remediation, which is the point: Step 1 re-enabled
protection, so `DescribeTable` still emits `DeletionProtectionEnabled` and a partial fix — the
common real outcome, where protection is restored but the table still has no recovery point —
lands on `[FAIL]` rather than being certified clean. Note what this check deliberately does
**not** claim: that the table's *contents* are intact. A table can be protected, backed up, and
still have had every item rewritten; that is a different use case
(`../dynamodb.impact.table-items-modified-or-destroyed/`) and a different assertion.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     eventSource dynamodb.amazonaws.com / eventName UpdateTable /"
echo "  requestParameters.deletionProtectionEnabled == false (JSON boolean, NOT the string"
echo "  \"false\") / no errorCode / userIdentity.arn NOT on the table-lifecycle allowlist."
echo "  The temporal correlation must fire critical when that principal's DeleteTable"
echo "  succeeds within 24 hours."
echo "MUST NOT fire on: UpdateTable carrying provisionedThroughput, billingMode,"
echo "  globalSecondaryIndexUpdates, streamSpecification, sSESpecification or replicaUpdates"
echo "  with deletionProtectionEnabled ABSENT - that is a different use case; an UpdateTable"
echo "  that returned AccessDeniedException or NotAuthorized; and deletionProtectionEnabled"
echo "  set to TRUE, which is the remediation."
echo "EXPECTED FP, by design: a planned decommission where the pipeline unprotects and then"
echo "  deletes. It fires critical and should - reconcile against the change record. If that"
echo "  is frequent, the finding is that decommissions are not going through change control."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the table-lifecycle pipeline could remove deletion protection | `dynamodb:UpdateTable` granted broadly because autoscaling needs it, with no SCP confining the `DeleteTable` it unlocks |
| The disable and the deletion were triaged as two unrelated P3 events | The source rule stops at the precondition; nothing correlated it to the destruction it was preparing |
| Nobody could say whether the deleted table was recoverable | PITR and backup state were never inventoried, and they are not in the CloudTrail event — after the deletion there is nothing left to ask |
| Most tables in the account were exposed the whole time and produced no event | Deletion protection is off by default, so the rule's population is only tables explicitly protected; its silence was read as coverage |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// StringNotLike is required because the value is wildcarded: Deny + StringNotEquals against a
// wildcarded ARN matches EVERY principal and denies table deletion outright - an outage, not a
// bypass. Note this denies DeleteTable, not UpdateTable: denying UpdateTable would break
// autoscaling on every table in the account.
{
  "Effect": "Deny",
  "Action": ["dynamodb:DeleteTable", "dynamodb:DeleteBackup"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

- The SCP reaches the caller because a DynamoDB control-plane call is always made by an
  in-organisation principal here. Pair it with deletion protection **and** PITR set at table
  creation in infrastructure code rather than switched on afterwards — both are off by default,
  and a table that is protected only because someone remembered is a table that will be created
  unprotected next time.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685 — Disable or Modify Tools (primary); T1485 — Data Destruction (secondary, and what the disable is *for*) |
| Primary API | `dynamodb:UpdateTable` with `DeletionProtectionEnabled: false`; `dynamodb:DeleteTable` as the second half |
| Event source | `dynamodb.amazonaws.com`, **management** plane, regional — verified against AWS's DynamoDB CloudTrail control-plane list, which enumerates `UpdateTable` and `DeleteTable` as logged by default |
| Key discriminator | `requestParameters.deletionProtectionEnabled`, a **JSON boolean**. `DeletionProtectionEnabled` is a parameter of `UpdateTable`, not an API — the event name alone cannot say what changed, and a rule matching `UpdateTable` fires on every capacity change |
| Field shape | `UpdateTable`: AWS's published example carries **no `tableName` in `requestParameters`**; the table is named at `responseElements.tableDescription.tableName` (nested wrapper). `DeleteTable`: `requestParameters.tableName`, plus `responseElements.tableDescription.itemCount` and `.tableSizeBytes`. `tableName` may legally be a full ARN |
| "Was it used" pivot | Whether a `DeleteTable` followed on the same table. There is no separate "was the unprotected state exercised" signal — the table either survived or it did not, and `DescribeTable` answers that directly |
| Blast radius | The table, its indexes, and its stream (`DISABLED`, auto-deleted after 24 hours). AWS: "Deleting a table is an unrecoverable operation." Recoverable only via a `$DeletedTableBackup` system snapshot, created **only if PITR was on**, retained 35 days — a single point in time, not the continuous range PITR offered while the table lived |
| Error strings | `UpdateTable` and `DeleteTable` both: `InternalServerError`, `LimitExceededException`, `ResourceInUseException`, `ResourceNotFoundException`. Plus DynamoDB Common Errors: `AccessDeniedException`, `NotAuthorized`, `ExpiredTokenException`, `IncompleteSignature`, `InternalFailure`, `MalformedHttpRequestException`, `OptInRequired`, `RequestAbortedException`, `RequestEntityTooLargeException`, `RequestTimeoutException`, `ServiceUnavailable`, `ThrottlingException`, `UnknownOperationException`, `UnrecognizedClientException`, `ValidationError` (**not** `ValidationException`). AWS documents the *behaviour* of deletion protection but **names no error** for a refused `DeleteTable` — do not branch on one |

### Residual Risk

If the table was deleted, it is gone, and no assertion in §5 changes that. A
`$DeletedTableBackup` restores the table as it stood at the instant of deletion and nothing
earlier — every item written and then overwritten during the incident is unrecoverable even
with a successful restore, and a restore "always restores to a new table" that does not carry
over auto scaling policies, IAM policies, CloudWatch metrics and alarms, tags, stream settings
or TTL settings, and comes back with deletion protection **off**. If PITR had already been
disabled before the deletion, there is no system backup at all and the only copies are whatever
on-demand backups predate the incident. Re-enabling PITR after the fact starts a new window
from that moment; the gap is permanent. And every table in the account that never had
protection turned on is still exactly as exposed as the one that alerted — the rule cannot see
them, because there was never a downgrade event to log.
