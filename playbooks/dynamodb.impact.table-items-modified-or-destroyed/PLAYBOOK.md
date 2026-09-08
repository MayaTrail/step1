# IR Playbook: DynamoDB Items Destroyed or Modified — and the `UpdateContinuousBackups` that made it permanent

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Impact — table items are deleted or overwritten, with the recovery configuration frequently removed first |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical for removal of point-in-time recovery or deletion protection, and for a TTL configuration whose deletions AWS never logs; medium for the item events themselves, which require data events to be visible at all |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485; T1565.001 |
| Services in Scope | DynamoDB, DynamoDB Streams, CloudTrail |

**What the technique does:** the actor destroys or alters table items. What makes this playbook
different from the rest of the set is that **the act itself is usually not recorded**. AWS splits
DynamoDB's CloudTrail coverage: `DeleteItem`, `UpdateItem`, `BatchWriteItem` and
`TransactWriteItems` are **data-plane** events, off by default and billable. In a default account,
both source rules are inert.

So the detections lead with what *is* logged — the control-plane preconditions that decide whether
the loss is recoverable:

| Event | Effect |
|---|---|
| `UpdateContinuousBackups` off | No point-in-time restore |
| `UpdateTable` deletion protection off | The table itself can be deleted |
| `UpdateTimeToLive` | Bulk deletion on a schedule, whose deletions AWS **never** logs |

**Why the usual reflexes miss it.** The first is reading "no results" as a clean result, when data
events were never enabled. The second is scoping rules to the classic API: PartiQL reaches the same
writes as `ExecuteStatement`, `BatchExecuteStatement` and `ExecuteTransaction`. The third is waiting
for TTL deletions to appear — they never will, at any log level. The fourth is assuming PITR is
available; it is off by default per table and its removal is the quiet first move.

**Detection thesis:** rate the control-plane preconditions highest because they are the only signals
present in every account, include the PartiQL names, and treat `UpdateTimeToLive` as destruction
rather than configuration.

**Adjacent playbooks.** Bulk reads are `../dynamodb.collection.table-scanned/`. Table configuration
more broadly is `../dynamodb.defense-evasion.table-configuration-modified/`. Mass table creation is
`../dynamodb.impact.multiple-tables-created/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

**Point-in-time recovery enabled on every table that matters.** This is the prerequisite the whole
response depends on. PITR restores to any second in the retention window; without it, deleted items
are gone and the incident has no recovery path. It is off by default, per table.

**DynamoDB data events, at least on tables holding regulated or sensitive data.** Without them the
item-level rules cannot fire and "what was deleted" is unanswerable. The cost objection has a
documented answer: AWS notes internal `GetRecords` calls inflate volume and recommends the *Exclude
AWS service-initiated events* selector template, or an advanced selector with `userIdentity.arn`
`NotStartsWith` `AWSServiceRoleFor`.

**DynamoDB Streams with `OLD_IMAGE` or `NEW_AND_OLD_IMAGES`** on tables where modification matters.
CloudTrail records that `UpdateItem` happened, never what the item held before — Streams is
frequently the only record of the previous values, and the view type is chosen long before it is
needed.

**Deletion protection on production tables.**

**Alerting (must be pre-configured)**

- **`UpdateContinuousBackups` disabling PITR, or `UpdateTable` removing deletion protection → P0**
- **Recovery removed and items destroyed by the same principal within 1h → P0**
- **`UpdateTimeToLive` on a table by a principal outside the provisioning path → P0**

**Response Tooling**

An IAM principal that can call `dynamodb update-continuous-backups`,
`restore-table-to-point-in-time`, `describe-continuous-backups`, `describe-time-to-live` and
`describe-table` outside the change pipeline.

Access to the Streams shard iterator for the affected table, if modification is in scope.

**Known IOC Baselines**

The application roles that legitimately write items, populating `known_provisioners`. Item writes
are overwhelmingly ordinary traffic, so without this list the item rules are unusable even where data
events are on.

The TTL configuration per table, recorded. A change is only visible as a difference and AWS keeps no
previous value.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `UpdateContinuousBackups` disabling PITR, or `UpdateTable` setting `deletionProtectionEnabled` false | CloudTrail (management) | T1485 |
| P0 | Recovery removed and items destroyed by the same principal within 1h | Correlation rule | T1485 |
| P0 | `UpdateTimeToLive` by a principal outside the provisioning path — deletions that follow are never logged | CloudTrail (management) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | Item deletion via `DeleteItem`, `BatchWriteItem` or a PartiQL `DELETE`, by a principal outside the application allowlist | CloudTrail (**data events**) | T1485 |
| P2 | Item modification via `PutItem`, `UpdateItem`, `TransactWriteItems` or PartiQL | CloudTrail (**data events**) | T1565.001 |
| P2 | `DeleteBackup` on a table's on-demand backups — removing the alternative recovery path | CloudTrail (management) | T1485 |

### Detection Rule Quality Notes

Both source rules are threshold queries and fully readable, so every row below is auditable against
`_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Both rules are data-plane and neither says so | `DeleteItem`, `BatchWriteItem`, `UpdateItem` and `TransactWriteItems` require data events, which are off by default and billable. In a default account **both rules are inert**, and "no results" is indistinguishable from a clean result | The precondition is stated in each rule's description, and the routable detections are the control-plane preconditions that fire in every account |
| No PartiQL coverage | `ExecuteStatement`, `BatchExecuteStatement` and `ExecuteTransaction` reach the same writes. AWS states CloudTrail captures both API styles. A `DELETE FROM` matches neither rule | All three names added to both rules |
| No coverage of the recovery configuration | PITR, deletion protection and backups decide whether the incident is recoverable, and all three are control-plane and logged by default — the only DynamoDB signals present without buying data events | Dedicated rules at critical, plus an ordered correlation with the destruction |
| No coverage of TTL | AWS never logs TTL deletions, at any level. A short TTL removes items in bulk with no record of any deletion | `UpdateTimeToLive` at high, treated as destruction rather than configuration |
| `NOT _exists_:errorMessage` rather than `errorCode` | `errorCode` is CloudTrail's canonical failure field; `errorMessage` is not always present, so the filter admits some failed calls as successes | `errorCode: null` |
| MITRE `T1505 — Server Software Component`, Persistence | That technique is about web shells and server software modules. It has no relationship to writing rows to a table | `T1485` for deletion, `T1565.001` for modification |

**Recommended detection — control plane first, because it is what exists.**

```yaml
# DynamoDB table items modified or destroyed (T1485 / T1565.001)
#
# BOTH SOURCE RULES ARE DATA-PLANE AND NEITHER SAYS SO. AWS splits DynamoDB's CloudTrail coverage
# explicitly: DeleteItem, BatchWriteItem, UpdateItem and TransactWriteItems are data-plane events,
# and "to enable logging of the following API actions in CloudTrail files, you must enable logging of
# data plane API activity". Data events are off by default and billable. So both rules are INERT in
# a default account, and a responder reading no results cannot tell "it did not happen" from "it was
# never recorded".
#
# THEREFORE THE ROUTABLE DETECTIONS HERE ARE THE CONTROL-PLANE PRECONDITIONS, which are logged by
# default and which decide whether destruction is recoverable at all:
#   UpdateContinuousBackups disabling PITR  -> no point-in-time restore
#   UpdateTable disabling deletion protection -> the table itself can go
#   UpdateTimeToLive                         -> bulk deletion on a schedule
# Those fire in every account. The item rules ship alongside them and are honest about needing data
# events.
#
# PARTIQL IS A COMPLETE BYPASS OF ANY ITEM-LEVEL RULE. The same writes are reachable as
# ExecuteStatement, BatchExecuteStatement and ExecuteTransaction — AWS states CloudTrail captures
# calls "using both PartiQL and the classic API". A `DELETE FROM` issued through ExecuteStatement
# does exactly what DeleteItem does and matches neither source rule. All three names are included.
#
# AND TTL DELETIONS ARE INVISIBLE. AWS: "DynamoDB Time to Live data plane actions are not logged by
# CloudTrail." An actor who sets a short TTL causes bulk deletion producing NO record of any
# deletion — not a data event, not a management event. `UpdateTimeToLive` is logged, so the
# configuration change is the only opportunity, and it ships at high for that reason.
#
# The source rules also filter on `NOT _exists_:errorMessage` rather than `errorCode`. CloudTrail's
# canonical failure field is errorCode; errorMessage is not always present on a failure, so the
# filter admits some failed calls as successes.
title: DynamoDB point-in-time recovery or deletion protection disabled
id: 5c1e7093-6ba4-42d8-97f0-31e802a5db64
name: dynamodb_recovery_protection_disabled
status: experimental
description: >-
  Continuous backups (PITR) turned off, or deletion protection removed. Both are control-plane and
  logged by default, so unlike the item-level rules these fire in every account. They are the
  precondition that turns item destruction from recoverable into permanent, and removing them
  before destroying anything is the ordering that matters.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  # Sibling blocks: two complete alternative shapes of "recovery was removed". Within each, the keys
  # are ANDed and they do co-occur on a single event — the record carries eventSource, eventName and
  # the submitted setting together.
  pitr_off:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'UpdateContinuousBackups'
    requestParameters.pointInTimeRecoverySpecification.pointInTimeRecoveryEnabled: false
  protection_off:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'UpdateTable'
    requestParameters.deletionProtectionEnabled: false
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own table lifecycle.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: (pitr_off or protection_off) and success and not known_provisioners
falsepositives:
  - >-
    A table being decommissioned, where protection is removed before deletion. The deletion that
    follows is the corroborating evidence, and its absence is what makes this worth reading.
level: critical
---
title: DynamoDB time-to-live configured
id: b704e2c8-3f19-4d56-a0b1-7e26c9834f5d
name: dynamodb_ttl_configured
status: experimental
description: >-
  UpdateTimeToLive succeeded. This is bulk deletion on a schedule, and AWS does not log the
  deletions it causes — "DynamoDB Time to Live data plane actions are not logged by CloudTrail." So
  items disappear afterwards with no record of any deletion at all, and this configuration event is
  the only opportunity to see it coming. Control-plane, logged by default, and therefore visible even
  where data events are not enabled.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'UpdateTimeToLive'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A genuine retention policy being applied, which is the common and correct use of TTL. The
    attribute name and the table are what distinguish it — the playbook reads the item population
    that would expire, because no event ever will.
level: high
---
title: DynamoDB items deleted, including through PartiQL
id: 9f38a06d-2c74-4b19-85e3-d0176ba4e298
name: dynamodb_items_destroyed
status: experimental
description: >-
  Items removed by DeleteItem, BatchWriteItem, or the PartiQL equivalents. REQUIRES DYNAMODB DATA
  EVENTS — these are data-plane operations, off by default and billable, so this rule is inert
  unless they were purchased. PartiQL is included because ExecuteStatement can issue a DELETE that
  does exactly what DeleteItem does and matches neither source rule.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName:
      - 'DeleteItem'
      - 'BatchWriteItem'
      - 'ExecuteStatement'
      - 'BatchExecuteStatement'
      - 'ExecuteTransaction'
  # CloudTrail's canonical failure field is errorCode. The source rules filter on errorMessage,
  # which is not always present on a failure and therefore admits some failed calls.
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    Ordinary application traffic, which is overwhelmingly what these events are. This rule is only
    usable with a populated allowlist of application roles, and even then the volume correlation is
    the routable output rather than the single event.
level: medium
---
title: DynamoDB items modified, including through PartiQL
id: 3a92c5e0-84fb-4d67-91a2-0c58e37b1d4f
name: dynamodb_items_modified
status: experimental
description: >-
  Items written or overwritten by PutItem, UpdateItem, TransactWriteItems, or the PartiQL
  equivalents. REQUIRES DYNAMODB DATA EVENTS. Modification is separated from deletion because the
  response differs: a deletion is restored from PITR, while a modification needs establishing what
  changed — and DynamoDB Streams is frequently the only record of the previous values.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1565/001/
tags:
  - attack.impact
  - attack.t1565.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName:
      - 'PutItem'
      - 'UpdateItem'
      - 'TransactWriteItems'
      - 'ExecuteStatement'
      - 'BatchExecuteStatement'
      - 'ExecuteTransaction'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    Ordinary application traffic. As with the deletion rule, the allowlist is mandatory and the
    correlation is what should be routed.
level: medium
---
title: DynamoDB recovery removed and items then destroyed
id: e10b76f4-95da-4c28-b3e7-6a2851f0c9db
status: experimental
description: >-
  Point-in-time recovery or deletion protection was removed and items were destroyed afterwards by
  the same principal. This is the ordering that turns a recoverable incident into a permanent one,
  and the first half is control-plane — so it is visible even in accounts where the second half is
  not recorded at all.
references:
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: temporal_ordered
  rules:
    - dynamodb_recovery_protection_disabled
    - dynamodb_items_destroyed
  group-by:
    - userIdentity.arn
  timespan: 1h
level: critical
```

What this set structurally cannot do: see a TTL deletion. AWS does not log them at any level, so the
`UpdateTimeToLive` event is the entire record and §2 Query 3 reads the affected items rather than
waiting for events that will never arrive.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> DynamoDB is **regional**. Item-level events appear only if **data events** are enabled — Query 1
> establishes that before anything else.

Run Query 1 first; whether data events exist changes how every later result should be read.

#### Query 1 — Establish what is even being recorded

```bash
REGION="${AWS_REGION:-us-east-1}"

echo "=== Does any trail record DynamoDB data events? ==="
aws cloudtrail list-trails --region "$REGION" --query 'Trails[].TrailARN' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    aws cloudtrail get-event-selectors --trail-name "$T" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg t "$T" 'if (tostring | test("AWS::DynamoDB::Table"))
                          then "[OK] \($t) records DynamoDB data events" else empty end'
  done

cat <<'NOTE'

[!] If nothing printed [OK], DeleteItem / UpdateItem / BatchWriteItem / PartiQL are NOT recorded in
    this account. Both source rules are inert, and any empty result from Query 2 means
    "not recorded" — never "did not happen". Say that in the report rather than reporting a
    negative finding.
NOTE

echo "=== Recovery posture, which IS logged by default ==="
aws dynamodb list-tables --region "$REGION" --query 'TableNames[]' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r TBL; do
    [ -z "$TBL" ] && continue
    P="$(aws dynamodb describe-continuous-backups --table-name "$TBL" --region "$REGION" \
          --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' \
          --output text 2>/dev/null)"
    D="$(aws dynamodb describe-table --table-name "$TBL" --region "$REGION" \
          --query 'Table.DeletionProtectionEnabled' --output text 2>/dev/null)"
    [ "$P" = "ENABLED" ] && echo "[OK] $TBL  PITR=$P  deletionProtection=$D" \
                         || echo "[!] $TBL  PITR=$P  deletionProtection=$D — no point-in-time restore"
  done
```

#### Query 2 — Reconstruct: the control-plane sequence, then the items if recorded

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in UpdateContinuousBackups UpdateTimeToLive UpdateTable DeleteTable DeleteBackup \
           DeleteItem BatchWriteItem ExecuteStatement BatchExecuteStatement; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # Control-plane events are logged by default; the item ones are not. Marking which is which
      # keeps a reader from treating an empty item section as a clean result.
      | (if (.eventName | test("^(UpdateContinuousBackups|UpdateTimeToLive|UpdateTable|DeleteTable|DeleteBackup)$"))
         then "CONTROL" else "data(requires data events)" end) as $plane
      | (if .eventName == "UpdateContinuousBackups" and
             ($r.pointInTimeRecoverySpecification.pointInTimeRecoveryEnabled == false)
         then "  *** PITR DISABLED ***"
         elif .eventName == "UpdateTable" and ($r.deletionProtectionEnabled == false)
         then "  *** DELETION PROTECTION REMOVED ***"
         elif .eventName == "UpdateTimeToLive"
         then "  *** TTL SET — deletions will NOT be logged ***"
         else "" end) as $flag
      | "\(.eventTime)  \(.eventName)  [\($plane)]  table=\($r.tableName // "-")  by=\(.userIdentity.arn)\($flag)"'
done | sort
```

Read the `***` lines as a sequence. Recovery removed *before* destruction is the ordering that makes
the loss permanent, and it is visible even in accounts where the destruction itself is not.

#### Query 3 — What a TTL configuration will remove, since nothing will log it

```bash
TABLE="${1:?table name from Query 2}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== Current TTL configuration ==="
aws dynamodb describe-time-to-live --table-name "$TABLE" --region "$REGION" --output json 2>/dev/null \
| jq -r '"  status:    \(.TimeToLiveDescription.TimeToLiveStatus)",
         "  attribute: \(.TimeToLiveDescription.AttributeName // "none")"'

cat <<'NOTE'

[!] AWS does NOT log TTL deletions — not as a data event, not as a management event, not at any
    level. So the item population that will expire cannot be recovered from CloudTrail afterwards,
    and this is the ONLY chance to record it.

    Capture it now, before the expiry runs. With the TTL attribute name from above:

      aws dynamodb scan --table-name <table> \
        --filter-expression "attribute_exists(#ttl) AND #ttl < :now" \
        --expression-attribute-names '{"#ttl":"<attribute>"}' \
        --expression-attribute-values '{":now":{"N":"<unix-epoch-now>"}}' \
        --select COUNT

    A non-zero count is the number of items that will disappear with no event. Run it with
    --select ALL_ATTRIBUTES and save the output if the contents matter.
NOTE
```

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 2 required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

# For an assumed role the CloudTrail username is the SESSION name: the second slash-separated
# segment after `assumed-role/`, not the role name and not the last segment.
case "$PRINCIPAL" in
  *:assumed-role/*) LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')" ;;
  *)                LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" ;;
esac

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$LOOKUP" \
  --start-time "$START" --region "$REGION" --max-results 200 \
  --query 'Events[].[EventTime,EventName,EventSource]' --output text 2>/dev/null | sort
```

`DescribeContinuousBackups` or `DescribeTable` before the change is the reconnaissance half — reading
whether PITR is on tells an actor whether destruction would be permanent.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore the recovery configuration first. It is one call, and until PITR is back on, every minute of
further destruction is unrecoverable rather than merely damaging.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 shows PITR
disabled, the window since that moment has no restore point. Re-enabling starts a **new** window; it
does not backfill. Anything destroyed in between is gone, and establishing what that was becomes the
priority.

#### Step 1 — Re-enable recovery

```bash
TABLE="${1:?table name}"
REGION="${AWS_REGION:-us-east-1}"

aws dynamodb update-continuous-backups --table-name "$TABLE" --region "$REGION" \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true \
  && echo "[OK] PITR re-enabled on $TABLE"

aws dynamodb update-table --table-name "$TABLE" --region "$REGION" \
  --deletion-protection-enabled >/dev/null 2>&1 \
  && echo "[OK] deletion protection re-enabled on $TABLE"

echo "[!] Re-enabling PITR starts a NEW recovery window. It does not backfill — the period while it"
echo "    was off has no restore point and never will."
```

#### Step 2 — Stop a pending TTL expiry

```bash
TABLE="${1:?table name}"
REGION="${AWS_REGION:-us-east-1}"

ATTR="$(aws dynamodb describe-time-to-live --table-name "$TABLE" --region "$REGION" \
         --query 'TimeToLiveDescription.AttributeName' --output text 2>/dev/null)"
STATUS="$(aws dynamodb describe-time-to-live --table-name "$TABLE" --region "$REGION" \
           --query 'TimeToLiveDescription.TimeToLiveStatus' --output text 2>/dev/null)"

if [ "$STATUS" = "ENABLED" ] || [ "$STATUS" = "ENABLING" ]; then
  echo "[!] TTL is $STATUS on attribute '$ATTR'. Disabling stops FUTURE expiry only —"
  echo "    anything already expired is gone and was never logged."
  read -r -p "Disable TTL on ${TABLE}? [y/N] " ANS
  [ "$ANS" = "y" ] && aws dynamodb update-time-to-live --table-name "$TABLE" --region "$REGION" \
    --time-to-live-specification "Enabled=false,AttributeName=${ATTR}" \
    && echo "[OK] TTL disabled on $TABLE"
else
  echo "[OK] TTL is $STATUS on $TABLE"
fi
```

#### Step 3 — Contain the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 2 required}"

case "$PRINCIPAL" in
  *:user/*)
    U="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')"
    aws iam list-access-keys --user-name "$U" --query 'AccessKeyMetadata[].AccessKeyId' \
      --output text 2>/dev/null | tr '\t' '\n' | while read -r K; do
        [ -z "$K" ] && continue
        aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
          && echo "[OK] key $K deactivated"
      done
    ;;
  *:assumed-role/*)
    # Role name is the FIRST segment after `assumed-role/`; the second is the session name.
    R="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $1}')"
    echo "[!] assumed role: $R — existing session credentials remain valid until expiry."
    echo "    Save as revoke.json and attach with put-role-policy:"
    cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"}}}]}
JSON
    echo "[!] If $R is the APPLICATION role, revoking it takes the application down. Weigh that"
    echo "    against continued writes to a table whose recovery is already compromised."
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

#### Step 4 — Restore, if there is a restore point

```bash
TABLE="${1:?table name}"
RESTORE_TO="${2:?ISO8601 timestamp just before the destruction}"
REGION="${AWS_REGION:-us-east-1}"

EARLIEST="$(aws dynamodb describe-continuous-backups --table-name "$TABLE" --region "$REGION" \
             --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.EarliestRestorableDateTime' \
             --output text 2>/dev/null)"
echo "Earliest restorable point: ${EARLIEST:-none}"

if [ -z "$EARLIEST" ] || [ "$EARLIEST" = "None" ]; then
  echo "[FAIL] no restore point exists — PITR was not enabled. Check on-demand backups:"
  aws dynamodb list-backups --table-name "$TABLE" --region "$REGION" \
    --query 'BackupSummaries[].[BackupName,BackupCreationDateTime]' --output text 2>/dev/null
else
  # Restores go to a NEW table. The original is left intact, which is what makes this safe to run
  # while the investigation continues.
  aws dynamodb restore-table-to-point-in-time --region "$REGION" \
    --source-table-name "$TABLE" --target-table-name "${TABLE}-restored" \
    --restore-date-time "$RESTORE_TO" \
    && echo "[OK] restoring to ${TABLE}-restored — compare before cutting over"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Establish what was lost, and be honest about what cannot be established

Three cases, and they end differently:

- **Data events on, PITR on** — the deletions are enumerable and restorable. This is the good case
  and it exists only because of decisions made months earlier.
- **Data events off, PITR on** — you can restore, but you cannot say what was destroyed without
  diffing the restored table against the live one. Do that diff; it is the only path to an answer.
- **TTL expiry** — nothing was logged at any level. The population is unrecoverable unless Query 3
  was run before the expiry, and the report should say so plainly.

#### Enable PITR everywhere, and deletion protection on production tables

These are the controls that determine whether the next occurrence is recoverable. Both are
control-plane, both are cheap, and both are off by default.

#### Turn on data events for tables holding regulated data

Without them "what was deleted" is permanently unanswerable, and the cost objection has a documented
remedy — the *Exclude AWS service-initiated events* template removes the internal `GetRecords`
traffic that inflates the bill.

#### Deny recovery removal outside the provisioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyDynamoDBRecoveryRemoval",
  "Effect": "Deny",
  "Action": ["dynamodb:UpdateContinuousBackups", "dynamodb:DeleteBackup",
             "dynamodb:UpdateTimeToLive", "dynamodb:DeleteTable"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. `UpdateTimeToLive` is included deliberately: denying the loud
destruction paths while leaving the unlogged one available closes the wrong door.

---

## 5. Recovery

### Restore Clean State

#### Verify recovery configuration across every table

```bash
REGION="${AWS_REGION:-us-east-1}"
FAIL=0

aws dynamodb list-tables --region "$REGION" --query 'TableNames[]' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r TBL; do
    [ -z "$TBL" ] && continue
    P="$(aws dynamodb describe-continuous-backups --table-name "$TBL" --region "$REGION" \
          --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' \
          --output text 2>/dev/null)"
    D="$(aws dynamodb describe-table --table-name "$TBL" --region "$REGION" \
          --query 'Table.DeletionProtectionEnabled' --output text 2>/dev/null)"
    if [ "$P" = "ENABLED" ] && [ "$D" = "True" ]; then
      echo "[OK] $TBL"
    else
      echo "[FAIL] $TBL  PITR=$P  deletionProtection=$D"
    fi
  done
```

#### Verify the restore matches expectation before cutting over

```bash
TABLE="${1:?original table name}"
RESTORED="${2:?restored table name}"
REGION="${AWS_REGION:-us-east-1}"

for T in "$TABLE" "$RESTORED"; do
  N="$(aws dynamodb describe-table --table-name "$T" --region "$REGION" \
        --query 'Table.ItemCount' --output text 2>/dev/null)"
  S="$(aws dynamodb describe-table --table-name "$T" --region "$REGION" \
        --query 'Table.TableStatus' --output text 2>/dev/null)"
  echo "  $T  status=$S  itemCount=$N"
done

echo "[!] ItemCount updates roughly every six hours and is NOT exact — treat it as an indication,"
echo "    not a reconciliation. A real comparison needs a scan of both tables on the key attribute."
```

#### Confirm the corrected detection fires

```bash
TABLE="${1:?a NON-PRODUCTION table name}"
REGION="${AWS_REGION:-us-east-1}"

# Exercise the CONTROL-PLANE path, which is the routable one and which works whether or not data
# events are enabled. Deletion protection is toggled rather than PITR, because disabling PITR
# genuinely discards the recovery window even on a test table.
aws dynamodb update-table --table-name "$TABLE" --region "$REGION" \
  --no-deletion-protection-enabled >/dev/null 2>&1 \
  && echo "[OK] deletion protection removed — expect the CRITICAL rule within 15 min"

sleep 60
aws dynamodb update-table --table-name "$TABLE" --region "$REGION" \
  --deletion-protection-enabled >/dev/null 2>&1 && echo "[OK] restored"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Were DynamoDB data events enabled? | Decides whether "what was deleted" is answerable at all, and whether an empty result means anything. |
| Was PITR on at the time? | The difference between a restore and a permanent loss, and it was decided months earlier. |
| Was recovery removed before the destruction? | That ordering is deliberate, and it is visible even where the destruction is not. |
| Was TTL involved? | If so, nothing was logged at any level and the population is unrecoverable unless it was captured beforehand. |
| Was PartiQL used? | `ExecuteStatement` matches no rule scoped to `DeleteItem`, so a hit there means the original coverage had a complete bypass. |
| Does Streams carry `OLD_IMAGE`? | For a modification it is usually the only record of the previous values. |

### Recommended Guardrails

**Enable PITR on every table.** It is the single control that determines whether this incident has an
ending. Off by default, per table.

**Treat `UpdateTimeToLive` as destruction.** AWS never logs the deletions it causes, so the
configuration event is the only opportunity and rating it as configuration guarantees it is missed.

**Cover the PartiQL event names.** Any rule scoped to the classic API has a complete bypass sitting
next to it.

**Say the data-event precondition in the rule.** A rule that is silently inert is worse than no rule,
because its empty output reads as a clean result.

**Deny recovery removal by SCP**, including `UpdateTimeToLive`. Denying the loud paths and leaving the
unlogged one is the wrong half.

### Technique Reference

**T1485 — Data Destruction** for deletion and **T1565.001 — Data Manipulation: Stored Data
Manipulation** for modification. Both verified live at https://attack.mitre.org/techniques/T1485/ and
https://attack.mitre.org/techniques/T1565/001/ on 2026-08-30.

The source pack maps both rules to **`T1505 — Server Software Component`** under Persistence. That
technique covers web shells and server software modules; it has no relationship to writing rows to a
table. It is among the least defensible mappings in this source set.

AWS references relied on throughout, all verified 2026-08-30:

- DynamoDB CloudTrail logging — the control/data plane split, the PartiQL coverage statement, the TTL
  exclusion, and the internal-`GetRecords` cost note:
  https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html

Service-wide verified behaviour shared by every `dynamodb.*` playbook is in
`../_ground-truth/dynamodb.md`.

### Residual Risk

**TTL deletions are unloggable.** Not a gap in configuration — AWS does not emit them at any level.
An estate that misses the `UpdateTimeToLive` event will see items disappear with nothing in
CloudTrail to explain it, and no setting changes that.

**Re-enabling PITR does not backfill.** The window while it was off has no restore point and never
will, so the value of Step 1 is entirely forward-looking.

**`ItemCount` is not a reconciliation.** It updates roughly every six hours and is approximate, so
"the counts match" is not evidence the restore is complete.

**Data events are expensive on a busy table.** The honest position is that they are worth buying for
tables holding regulated data and hard to justify for high-volume application tables — which means
some tables will remain in the state where this playbook's item rules cannot fire, and the
control-plane rules are all there is.
