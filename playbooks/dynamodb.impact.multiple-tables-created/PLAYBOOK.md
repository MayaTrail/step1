# IR Playbook: DynamoDB Tables Created at Volume — capacity consumption via `CreateTable`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Impact — tables are created in volume, consuming capacity and cost, or created to stage data for extraction |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Medium for volume; high when a newly created table is written into by a non-provisioning principal. A single empty table is not a finding. The source rule is P4 and cannot fire. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1496 |
| Services in Scope | DynamoDB, CloudTrail |

**What the technique does:** the actor creates tables. An empty table contains no data, so on its own
this consumes capacity and money rather than exposing anything. The shape that matters is a table
created and then **written into** — that is staging for extraction, and the extraction is the finding.

**Why the usual reflexes miss it.** The first is the event name: the source rule is lowercase and
cannot fire. The second is the threshold — five tables in sixty seconds is a deployment burst, so the
rule is tuned to catch the pipeline and miss a patient actor. The third is treating a new table as
data manipulation, which it cannot be. The fourth is stopping at the creation, when the write that
follows is what turns it into an incident.

**Detection thesis:** widen the window and let the provisioning allowlist discriminate; rate the
creation low and the creation-then-write high.

**Adjacent playbooks.** Reads out of a table are `../dynamodb.collection.table-scanned/`. Writes and
deletions are `../dynamodb.impact.table-items-modified-or-destroyed/`. Configuration changes are
`../dynamodb.defense-evasion.table-configuration-modified/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `CreateTable` is control-plane and logged by default,
so unlike most DynamoDB detections this one needs nothing purchased.

A service-quota alarm on table count per region. Resource consumption is the primary impact, and the
quota is where it lands first.

**Alerting (must be pre-configured)**

- **A table created and written into by a non-provisioning principal within the hour → P0**
- **Five or more tables created in ten minutes by a principal outside the provisioning path → P1**
- **Five or more tables created in ten minutes by any principal → P2**

**Response Tooling**

An IAM principal that can call `dynamodb list-tables`, `describe-table` and `delete-table` outside
the change pipeline.

**Known IOC Baselines**

The roles that own table lifecycle, populating `known_provisioners`. Deployments create tables in
bursts, so without this list the volume correlation is dominated by them.

The expected table-name conventions. A table created outside them is worth reading even at low
volume.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | A table created and then written into by a non-provisioning principal within the hour | CloudTrail (mixed) | T1496 |
| P1 | Five or more tables created in ten minutes by a principal outside the provisioning path | Correlation rule | T1496 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | Five or more tables created in ten minutes by any principal — almost always a deployment | Correlation rule | T1496 |
| P2 | A table created outside the naming convention | CloudTrail + inventory | T1496 |
| P3 | A single table created by a principal outside the provisioning path | CloudTrail | T1496 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"createtable"` — lowercase | CloudTrail emits `CreateTable`. On a case-sensitive field the rule matches nothing and **cannot fire** | Documented casing |
| Threshold of five in sixty seconds | A deployment burst reaches it; a person creating tables by hand does not. Tuned to catch the traffic it should ignore and to miss a slower actor | Ten-minute window, with the provisioning allowlist doing the discrimination |
| Rated as data manipulation | `CreateTable` produces a resource containing no data. There is nothing to manipulate | `T1496 — Resource Hijacking`, which is what capacity and cost consumption is |
| Stops at the creation | An empty table is not a finding. A table created and written into is staging for extraction | A creation-then-write shape surfaced in the query and rated above the volume case |
| No principal dimension | Deployments create tables constantly; the identity is the only thing that separates them | `known_provisioners` on the base rule |

**Recommended detection — creation as context, creation-then-write as the finding.**

```yaml
# DynamoDB tables created at volume (T1496)
#
# THE RULE CANNOT FIRE. It matches `eventName:"createtable"`; CloudTrail emits `CreateTable`, and on
# a case-sensitive field the lowercase form matches nothing. This is the ninth instance of that
# defect class across the source set — see ../../_ground-truth/dynamodb.md §5.
#
# ITS THRESHOLD IS FIVE IN SIXTY SECONDS, WHICH IS A DEPLOYMENT. An infrastructure apply that stands
# up a new environment creates tables in a burst; a human creating tables by hand does not reach five
# in a minute. So the rule as written is tuned to catch exactly the traffic it should ignore, and to
# miss a slower actor entirely. Widened to ten minutes here, with the provisioning allowlist doing
# the actual work.
#
# AND IT MAPS TO DATA MANIPULATION. `T1565` is about altering stored or transmitted data. Creating an
# empty table alters nothing — the resource is new and contains no data at all. What mass table
# creation actually costs is capacity and money: `T1496 — Resource Hijacking`. Where the tables are
# being created to stage data for extraction, the extraction is the finding and lives in
# ../../dynamodb.collection.table-scanned/
#
# `CreateTable` IS CONTROL-PLANE AND LOGGED BY DEFAULT, which makes this one of the few DynamoDB
# rules that works without buying data events — worth saying, because three of the five rules in this
# source set do not.
title: DynamoDB tables created at volume by one principal
id: 0d5a83f1-4e72-4b96-8c10-a37e6b25d0f9
status: experimental
description: >-
  One principal created five or more tables within ten minutes. The source rule uses sixty seconds,
  which is a deployment burst rather than a human, so the window is widened and the provisioning
  allowlist carries the discrimination. Control-plane and logged by default, so this fires without
  DynamoDB data events.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1496/
tags:
  - attack.impact
  - attack.t1496
correlation:
  type: value_count
  rules:
    - dynamodb_table_created
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 5
    field: requestParameters.tableName
falsepositives:
  - >-
    An environment build creating a table set in one run, which is exactly this shape. Allowlist the
    pipeline role on the base rule rather than shortening the window — a sixty-second window
    excludes the deployment and the actor alike.
level: medium
---
title: DynamoDB table created by a principal outside the provisioning path
id: 6c14e7ab-92d0-4f38-b571-8e0a3c62df45
name: dynamodb_table_created_unexpected
status: experimental
description: >-
  A successful CreateTable from a principal that is not a recorded provisioning identity. A single
  new table is not itself harmful — it is empty — so this ships at low and exists to make an
  unexpected creator visible and to give the volume correlation something to build on. A table
  created to stage data for extraction becomes a finding when something reads into it.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html
  - https://attack.mitre.org/techniques/T1496/
tags:
  - attack.impact
  - attack.t1496
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'CreateTable'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own table lifecycle.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    An engineer creating a table for development work, which is common and legitimate. Low severity
    for that reason — routed to a log rather than to a human, with the volume correlation carrying
    the alert.
level: low
---
title: DynamoDB table created
id: 8f7c02d5-63be-41a9-95e0-1d4b78e3ca62
name: dynamodb_table_created
status: experimental
description: >-
  Base rule — correlation component and change accounting, never for direct alerting. A successful
  CreateTable. Control-plane, so it is logged by default in every account.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html
tags:
  - attack.impact
  - attack.t1496
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'CreateTable'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: tell you what a new table is *for*. An empty table is
indistinguishable from a legitimate one until something uses it, which is why the write is the
discriminator.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> DynamoDB is **regional**. `CreateTable` is control-plane and logged by default, so unlike most
> DynamoDB queries these work without data events — except Query 2, which says so.

Run Query 1 first; it establishes whether the creations are a deployment or not.

#### Query 1 — Reconstruct: who created what, and was anything written into it

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in CreateTable DeleteTable BatchWriteItem PutItem; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # CreateTable is control-plane and always logged. BatchWriteItem and PutItem are DATA events —
      # if they are absent, that may be because data events are off, not because nothing was written.
      | (if (.eventName | test("^(CreateTable|DeleteTable)$")) then "CONTROL" else "data(requires data events)" end) as $plane
      | "\(.eventTime)  \(.eventName)  [\($plane)]  table=\($r.tableName // "-")  " +
        "billing=\($r.billingMode // "PROVISIONED")  by=\(.userIdentity.arn)"'
done | sort
```

Group the `CreateTable` lines by principal and count distinct table names inside a ten-minute window.
A burst from a pipeline role is a deployment. A `BatchWriteItem` or `PutItem` on a table created
minutes earlier by the same principal is the staging shape — and note the caveat: those are data
events, so their absence is not evidence.

#### Query 2 — What is in the new tables

```bash
REGION="${AWS_REGION:-us-east-1}"
TABLE="${1:?table name from Query 1}"

aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" --output json 2>/dev/null \
| jq -r '"  created:        \(.Table.CreationDateTime)",
         "  items (approx): \(.Table.ItemCount)",
         "  size (bytes):   \(.Table.TableSizeBytes)",
         "  billing:        \(.Table.BillingModeSummary.BillingMode // "PROVISIONED")",
         "  keys:           \([.Table.KeySchema[] | "\(.AttributeName)(\(.KeyType))"] | join(", "))"'

echo
echo "[!] ItemCount and TableSizeBytes update roughly every six hours, so a table populated in the"
echo "    last few hours may still report zero. A non-zero size on a table created recently by an"
echo "    unexpected principal is the staging shape confirmed."
```

#### Query 3 — Sweep: tables outside the naming convention

```bash
REGION="${AWS_REGION:-us-east-1}"
# POPULATE with this account's table-name prefixes.
CONVENTION="prod- staging- dev-"

aws dynamodb list-tables --region "$REGION" --query 'TableNames[]' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    MATCH=0
    for P in $CONVENTION; do case "$T" in ${P}*) MATCH=1 ;; esac; done
    if [ "$MATCH" -eq 1 ]; then
      echo "[OK] $T"
    else
      SZ="$(aws dynamodb describe-table --table-name "$T" --region "$REGION" \
             --query 'Table.TableSizeBytes' --output text 2>/dev/null)"
      echo "[!] $T — outside the naming convention, size=${SZ:-unknown}"
    fi
  done
```

A table outside the convention with a non-zero size is worth reading regardless of when it was
created — mass creation is the loud form of this technique and a single well-named staging table is
the quiet one.

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"
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

Look for `Scan` or `Query` on **other** tables around the creation. Creating a destination and
reading a source is the complete staging shape, and the read half is
`../dynamodb.collection.table-scanned/`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

An empty table is not urgent. What is urgent is whether anything was written into it, and whether the
principal was also reading elsewhere.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows writes into
a table created minutes earlier by a non-provisioning principal, treat this as data staging and go to
`../dynamodb.collection.table-scanned/` for the read side — the exfiltration is the incident and this
table is the destination.

#### Step 1 — Preserve before deleting

```bash
TABLE="${1:?table name}"
REGION="${AWS_REGION:-us-east-1}"

aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" --output json \
  > "./evidence-${TABLE}-describe.json" 2>/dev/null \
  && echo "[OK] table metadata preserved at ./evidence-${TABLE}-describe.json"

SZ="$(aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" \
       --query 'Table.TableSizeBytes' --output text 2>/dev/null)"
if [ "${SZ:-0}" != "0" ]; then
  echo "[!] $TABLE contains data (${SZ} bytes). Export it before deleting — the contents are"
  echo "    evidence of what was staged, and deletion is irreversible without PITR:"
  echo "    aws dynamodb scan --table-name $TABLE --region $REGION > ./evidence-${TABLE}-items.json"
fi
```

#### Step 2 — Contain the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"

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
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

#### Step 3 — Remove the tables, once preserved

```bash
REGION="${AWS_REGION:-us-east-1}"

echo "[!] Delete only tables confirmed unwanted and already preserved by Step 1. DeleteTable is"
echo "    irreversible without PITR or an on-demand backup."
for T in "$@"; do
  [ -z "$T" ] && continue
  P="$(aws dynamodb describe-table --table-name "$T" --region "$REGION" \
        --query 'Table.DeletionProtectionEnabled' --output text 2>/dev/null)"
  if [ "$P" = "True" ]; then
    echo "[!] $T has deletion protection — remove it deliberately first, it is doing its job"
  else
    read -r -p "Delete $T? [y/N] " ANS
    [ "$ANS" = "y" ] && aws dynamodb delete-table --table-name "$T" --region "$REGION" >/dev/null \
      && echo "[OK] $T deleted"
  fi
done
```

#### Step 4 — Check the quota impact

Mass table creation lands on the per-region table quota before it lands anywhere else. If the count
is near the limit, legitimate deployments will start failing — and that failure is often how the
incident is first noticed. Confirm headroom before closing.

---

## 4. Eradication

### Remove Attacker Access

#### Establish whether this was consumption or staging

The two endings are different. **Consumption** — many empty tables — costs money and quota and is
resolved by deleting them. **Staging** — one or a few tables being written into — means data was
being collected for extraction, and the incident is the read that fed it, not the table.

Query 1's write lines settle it, with the caveat that those are data events and their absence proves
nothing.

#### Scope `dynamodb:CreateTable`

It belongs to infrastructure automation. Review identity policies granting it, and every wildcard
(`dynamodb:*`) that grants it by accident — the wildcard is usually how it arrived.

#### Deny table creation outside the provisioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyDynamoDBTableCreationOutsideProvisioning",
  "Effect": "Deny",
  "Action": ["dynamodb:CreateTable"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. Test in a non-production OU first.

#### Alarm on the table-count quota

It is the earliest signal of the consumption form and it is independent of any detection rule.

---

## 5. Recovery

### Restore Clean State

#### Verify only expected tables remain

```bash
REGION="${AWS_REGION:-us-east-1}"
CONVENTION="prod- staging- dev-"
FAIL=0

aws dynamodb list-tables --region "$REGION" --query 'TableNames[]' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    MATCH=0
    for P in $CONVENTION; do case "$T" in ${P}*) MATCH=1 ;; esac; done
    [ "$MATCH" -eq 1 ] && echo "[OK] $T" || echo "[FAIL] $T outside the naming convention"
  done
```

#### Verify quota headroom has returned

```bash
REGION="${AWS_REGION:-us-east-1}"
N="$(aws dynamodb list-tables --region "$REGION" --query 'length(TableNames)' --output text 2>/dev/null)"
echo "tables in $REGION: ${N:-unknown}"
echo "[!] Compare against the account's table quota for this region. Deployments failing to create"
echo "    tables is often how this incident surfaces, and it persists until the count comes down."
```

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"
PREFIX="detection-test-$$"

# Exercise the VOLUME correlation. Five on-demand tables cost nothing at rest and are deleted
# immediately afterwards.
for i in 1 2 3 4 5; do
  aws dynamodb create-table --table-name "${PREFIX}-${i}" --region "$REGION" \
    --attribute-definitions AttributeName=id,AttributeType=S \
    --key-schema AttributeName=id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST >/dev/null 2>&1 && echo "[OK] created ${PREFIX}-${i}"
done
echo "[!] Expect the volume correlation within 15 min — NOT five separate low-severity alerts."

sleep 60
for i in 1 2 3 4 5; do
  aws dynamodb delete-table --table-name "${PREFIX}-${i}" --region "$REGION" >/dev/null 2>&1
done
echo "[OK] test tables deleted"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was anything written into the new tables? | The difference between capacity consumption and data staging, and therefore between a cost incident and an exfiltration one. |
| Was the principal a provisioning role? | Deployments create tables in bursts; that is the common explanation and the fastest to confirm. |
| Did the count approach the region's table quota? | Deployment failures are often how this is noticed, and they persist until the count comes down. |
| Were the tables named outside the convention? | Mass creation is the loud form; a single well-named staging table is the quiet one. |
| Was the same principal reading other tables? | Creating a destination and reading a source is the complete staging shape. |
| How did the principal hold `dynamodb:CreateTable`? | Usually via a `dynamodb:*` wildcard nobody intended to include it. |

### Recommended Guardrails

**Widen the window and use an allowlist.** A sixty-second threshold selects for deployments and
against patient actors — the opposite of what is wanted.

**Rate the write, not the creation.** An empty table is not a finding; a new table being populated by
an unexpected principal is.

**Alarm on the table-count quota.** It is independent of any rule and it catches the consumption form
first.

**Scope `dynamodb:CreateTable` to automation.** It is rarely needed elsewhere and the wildcard is how
it usually spreads.

**Enforce a table naming convention and sweep against it.** It makes the quiet single-table form
visible without any volume signal at all.

### Technique Reference

**T1496 — Resource Hijacking.** Verified live at https://attack.mitre.org/techniques/T1496/ on
2026-08-30. Consuming account capacity and quota is what this technique names.

The source rule maps to `T1565 — Data Manipulation`, which describes altering stored or transmitted
data. `CreateTable` produces an empty resource and alters nothing.

AWS references relied on throughout, all verified 2026-08-30:

- DynamoDB CloudTrail logging — the control-plane list confirming `CreateTable` is logged by default:
  https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
- `CreateTable` API reference:
  https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html

Service-wide verified behaviour shared by every `dynamodb.*` playbook is in
`../_ground-truth/dynamodb.md`.

### Residual Risk

**The staging form is only visible with data events.** Writes into a new table are data-plane, so in
an account without them the difference between an idle table and a populated one is
`TableSizeBytes` — which updates roughly every six hours and is approximate.

**A single staging table produces no volume signal at all.** The correlation needs five; one
well-named table written into quietly is the more likely real case, and the naming sweep in Query 3
is the only thing that surfaces it.

**Deleting an unwanted table destroys its contents.** If it was a staging table, those contents are
evidence of what was collected. Step 1's preservation is not optional in that case.

**`ItemCount` is approximate.** A table populated in the last few hours can still report zero, so a
zero reading shortly after creation is not evidence that nothing was written.
