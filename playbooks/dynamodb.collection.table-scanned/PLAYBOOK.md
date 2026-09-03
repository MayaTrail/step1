# IR Playbook: DynamoDB Tables Read at Breadth — bulk read via `dynamodb:Scan`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Collection — table contents are read in bulk, taking whatever the items hold out of the table |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High when reads span three or more tables or follow enumeration; medium for a full scan returning all attributes by an unexpected principal. The source rule is P4 and inert in a default account. |
| MITRE Tactics | Collection |
| MITRE Techniques | T1530 |
| Services in Scope | DynamoDB, CloudTrail |

**What the technique does:** the actor reads table contents. Whatever the items hold comes out —
personal data, tokens, session material, business records. As with any read, the act is complete on
the first call and nothing done afterwards undoes it.

**Why the usual reflexes miss it.** The first is not knowing the rule is off: `Scan` is a data-plane
operation, so in a default account the source rule never fires and its silence reads as a clean
result. The second is counting scans — analytics and export jobs scan constantly, so volume
reproduces the noise rather than separating anything. The third is ignoring `select`: a scan with
`select: COUNT` returns no item data at all and cannot be exfiltration, while `ALL_ATTRIBUTES`
returns everything. The fourth is watching only `Scan`, when `Query` and PartiQL `ExecuteStatement`
reach the same data under different event names.

**Detection thesis:** count **distinct tables** rather than scans, gate the single-event rule on
`select`, and cover all three read paths.

**Adjacent playbooks.** Writes and deletions are
`../dynamodb.impact.table-items-modified-or-destroyed/`. Table configuration is
`../dynamodb.defense-evasion.table-configuration-modified/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

**DynamoDB data events, at least on tables holding regulated or sensitive data.** Without them
nothing in this playbook can fire. The cost objection has a documented answer: AWS notes internal
`GetRecords` calls inflate volume and recommends the *Exclude AWS service-initiated events* selector
template, or an advanced selector with `userIdentity.arn` `NotStartsWith` `AWSServiceRoleFor`.

**A record of what each table's items contain that would matter if disclosed.** Containment here is
rotation, and rotating requires knowing what is in the rows. An estate that cannot answer that
cannot scope this incident.

The application roles that legitimately read each table. Scans are overwhelmingly ordinary traffic.

**Alerting (must be pre-configured)**

- **`ListTables` followed by reads across three or more tables by the same principal → P0**
- **Reads across three or more distinct tables in fifteen minutes by a principal outside the application set → P0**

**Response Tooling**

Read access to CloudTrail over the window, and the table schema so the disclosed attributes can be
identified.

**Known IOC Baselines**

The application roles per table, populating `known_readers`.

Normal read breadth per principal. An export job reading many tables is behaviourally identical to
the technique, and only knowing it exists separates them.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `ListTables` or `DescribeTable` followed by reads across three or more tables by the same principal | CloudTrail (mixed) | T1530 |
| P0 | Reads across three or more distinct tables in fifteen minutes by a principal outside the application set | Correlation rule | T1530 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | Reads across three or more distinct tables in fifteen minutes by any principal | Correlation rule | T1530 |
| P2 | `Scan` with `select: ALL_ATTRIBUTES` and no `Limit` by a principal outside the application set | CloudTrail (**data events**) | T1530 |
| P2 | Any read by a principal with no read history for that table | CloudTrail (**data events**) | T1530 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `Scan` is data-plane and the rule does not say so | Data events are off by default and billable, so the rule is inert in a default account and its silence reads as a clean result | The precondition is stated in every rule that carries it, and the query reports when it is the likely explanation for an empty result |
| No discriminator on an ordinary operation | Analytics and export jobs scan constantly. A rule that fires on any scan is noise; one that never fires is useless | Gated on `select`, and the routable output is a breadth correlation that needs no allowlist |
| `select` ignored | A scan with `select: COUNT` returns no item data and cannot be exfiltration. `ALL_ATTRIBUTES` returns everything. Rating them alike is what makes the rule unusable | The single-event rule requires `ALL_ATTRIBUTES` or `ALL_PROJECTED_ATTRIBUTES` |
| Watches `Scan` only | `Query` reads a partition — a great deal of it without a narrowing key condition — and PartiQL `ExecuteStatement` compiles a `SELECT` to either, under a different event name | All three in the base rule so the correlation sees them |
| `NOT _exists_:errorMessage` rather than `errorCode` | `errorCode` is the canonical failure field; `errorMessage` is not always present, so failed calls are admitted as successes | `errorCode: null` |
| MITRE `T1596 — Search Open Technical Databases` | A **Reconnaissance** technique about WHOIS, passive DNS and public scan databases — things the adversary does not own | `T1530 — Data from Cloud Storage` |

**Recommended detection — breadth as the signal, `select` as the gate.**

```yaml
# DynamoDB table scanned (T1530)
#
# `Scan` IS DATA-PLANE, SO THE SOURCE RULE IS INERT IN A DEFAULT ACCOUNT. AWS lists Scan among the
# operations for which "you must enable logging of data plane API activity in CloudTrail". Data
# events are off by default and billable. The rule does not say so, and an empty result from it means
# "not recorded" rather than "did not happen".
#
# AND IT MAPS TO A RECONNAISSANCE TECHNIQUE ABOUT PUBLIC SOURCES. `T1596 — Search Open Technical
# Databases` covers WHOIS, passive DNS, CDN and public scan databases — searching things the
# adversary does not own. Scanning your own DynamoDB table is reading stored data:
# `T1530 — Data from Cloud Storage`.
#
# `Scan` IS ALSO ORDINARY. Analytics jobs, exports and small-table lookups scan constantly, so a
# single Scan is not a finding and a flat threshold on scan COUNT reproduces the noise. Two things
# separate a walk from a workload and both are in the request:
#   * `select` — a scan with select COUNT returns no item data at all. Only ALL_ATTRIBUTES and
#     ALL_PROJECTED_ATTRIBUTES actually move the rows.
#   * BREADTH — an application scans its own table; a principal scanning several tables is not one.
#
# AND IT MISSES THE OTHER TWO READ PATHS. `Query` reads a partition and, without a key condition
# narrowing it, reads a great deal; PartiQL `ExecuteStatement` compiles a SELECT to a Scan or Query
# under a different event name entirely. Both are included below.
title: DynamoDB tables read at breadth by one principal
id: 7a41d6b8-0e93-4c25-b8f7-52d0916ae3fc
status: experimental
description: >-
  One principal read three or more distinct tables within fifteen minutes. Breadth is the signal
  rather than volume: an application scans its own table repeatedly and a walk touches several. This
  is the routable output of the directory, and it needs no allowlist to be meaningful.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
correlation:
  type: value_count
  rules:
    - dynamodb_table_read
  group-by:
    - userIdentity.arn
  timespan: 15m
  condition:
    gte: 3
    field: requestParameters.tableName
falsepositives:
  - >-
    A backup, export or analytics job that legitimately reads across tables. It is behaviourally
    identical to the technique, so allowlist it by role on the base rule — no threshold separates
    them.
level: high
---
title: DynamoDB full table scan returning item data
id: c2807e5a-96b1-4d34-a071-e6f5238b4d90
name: dynamodb_full_scan_returning_data
status: experimental
description: >-
  A Scan requesting ALL_ATTRIBUTES, by a principal outside the application allowlist. The `select`
  parameter is the discriminator the source rule ignores: a scan with select COUNT returns no item
  data at all, so it cannot be exfiltration, while ALL_ATTRIBUTES returns every attribute of every
  item examined. REQUIRES DYNAMODB DATA EVENTS.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Scan.html
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'Scan'
  returns_data:
    requestParameters.select:
      - 'ALL_ATTRIBUTES'
      - 'ALL_PROJECTED_ATTRIBUTES'
  # CloudTrail's canonical failure field is errorCode. The source rule filters on errorMessage, which
  # is not always present on a failure and therefore admits some failed calls.
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the application roles that legitimately scan.
  known_readers:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/app-runtime'
  condition: selection and success and returns_data and not known_readers
falsepositives:
  - >-
    An export or migration job reading a full table, which is exactly this shape. The allowlist is
    the only thing that separates them, and it has to be current.
level: medium
---
title: DynamoDB table read
id: 4e6b13da-58c7-49f0-9218-b7ac05e3f682
name: dynamodb_table_read
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful read across the
  three paths: Scan, Query, and the PartiQL statement forms which compile a SELECT to one of them.
  REQUIRES DYNAMODB DATA EVENTS. Application traffic produces these continuously.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName:
      - 'Scan'
      - 'Query'
      - 'ExecuteStatement'
      - 'BatchExecuteStatement'
      - 'BatchGetItem'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
title: DynamoDB table read by a principal with no read history
id: 91f0c47e-2b58-4d6a-83e1-70c5d829a4b3
name: dynamodb_table_read_unfamiliar_principal
status: experimental
description: >-
  A read of a table by a principal outside the recorded application set. One read has ordinary
  explanations — an engineer investigating — so this ships at low and exists to give the breadth
  correlation something to build on and to make an unexpected reader visible without paging anyone.
  REQUIRES DYNAMODB DATA EVENTS.
references:
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName:
      - 'Scan'
      - 'Query'
      - 'ExecuteStatement'
      - 'BatchExecuteStatement'
  success:
    errorCode: null
  known_readers:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/app-runtime'
  service_invoked:
    userIdentity.invokedBy|exists: true
  condition: selection and success and not known_readers and not service_invoked
falsepositives:
  - >-
    An application role missing from the list, which in an estate with many task roles is the common
    case. Low severity for that reason — routed to a log, not to a human.
level: low
```

What this set structurally cannot do: tell you what the items contained. That is a schema question,
answered outside AWS, and it is what determines the scope of the disclosure.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> DynamoDB is **regional**, and every read event here requires **data events** to exist at all.

Run Query 1 first; if data events are off, everything after it returns nothing for reasons that have
nothing to do with the incident.

#### Query 1 — Is anything being recorded

```bash
REGION="${AWS_REGION:-us-east-1}"

aws cloudtrail list-trails --region "$REGION" --query 'Trails[].TrailARN' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    aws cloudtrail get-event-selectors --trail-name "$T" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg t "$T" 'if (tostring | test("AWS::DynamoDB::Table"))
                          then "[OK] \($t) records DynamoDB data events" else empty end'
  done
echo "[!] If nothing printed [OK], Scan and Query are NOT recorded here. Queries 2 and 3 will be"
echo "    empty for that reason, and the correct finding is that the read is unobservable —"
echo "    not that no read occurred."
```

#### Query 2 — Reconstruct: breadth, `select`, and whether enumeration came first

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in Scan Query ExecuteStatement BatchExecuteStatement ListTables; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # select COUNT reads the table and returns only a number — it cannot be exfiltration.
      # Absent select defaults to returning attributes, so absence is treated as returning data.
      | (($r.select // "ALL_ATTRIBUTES")) as $sel
      | (if .eventName == "ListTables" then "ENUMERATE"
         elif $sel == "COUNT" then "read(COUNT — no item data)"
         elif ($r.limit == null) then "READ-ALL(no limit)"
         else "read(limited)" end) as $kind
      | "\(.eventTime)  \(.eventName)  \($kind)  table=\($r.tableName // "-")  by=\(.userIdentity.arn)"'
done | sort
```

Count **distinct tables** per principal, not rows. An `ENUMERATE` line before reads across several
tables is the strongest shape available — an application reads the table it was configured with and
does not look around first. A run of `read(COUNT — no item data)` moved nothing at all.

#### Query 3 — What the read exposed

```bash
TABLE="${1:?table name from Query 2}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== Table shape ==="
aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" --output json 2>/dev/null \
| jq -r '"  items (approx): \(.Table.ItemCount)",
         "  size (bytes):   \(.Table.TableSizeBytes)",
         "  keys:           \([.Table.KeySchema[] | "\(.AttributeName)(\(.KeyType))"] | join(", "))",
         "  encryption:     \(.Table.SSEDescription.SSEType // "AWS owned key")"'

cat <<'NOTE'

[!] DynamoDB is schemaless beyond the key attributes, so AWS cannot tell you what the items hold.
    Answer it from the application:
      [ ] which attributes carry personal data, tokens or credentials
      [ ] whether any attribute is a secret that can be rotated
      [ ] what cannot be rotated and must be recorded as disclosed

    A full scan returning ALL_ATTRIBUTES exposed every attribute of every item it examined. The
    ItemCount above is approximate — it updates roughly every six hours — so use it as an
    indication of scale, not as a count of what was taken.
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

Management events are complete regardless of the data-event setting, so this view is reliable even
when Queries 2 and 3 are empty — and `ListTables` here is often the only trace a read ever leaves.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The read has happened and cannot be undone. Containment is about the credential and about what the
items protect.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 shows reads
across several tables by a principal outside the application set, treat every attribute in those
tables as disclosed and begin rotation before completing the investigation — rotation is the long
pole and does not depend on knowing exactly who did it.

#### Step 1 — Revoke the credential

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
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

#### Step 2 — Narrow what the role could read

```bash
PRINCIPAL="${1:?principal ARN}"
REGION="${AWS_REGION:-us-east-1}"

case "$PRINCIPAL" in
  *:assumed-role/*)
    R="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $1}')"
    echo "=== Attached policies for $R ==="
    aws iam list-attached-role-policies --role-name "$R" \
      --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n' | sed 's/^/  /'
    aws iam list-role-policies --role-name "$R" --query 'PolicyNames' --output text 2>/dev/null \
      | tr '\t' '\n' | sed 's/^/  inline: /'
    ;;
esac

echo
echo "[!] The question is whether dynamodb:Scan / Query were granted on Resource: \"*\"."
echo "    Estate-wide read is what turns one compromised role into a walk across every table;"
echo "    scoped to its own table ARN, the same compromise reads one table."
```

#### Step 3 — Rotate what the items protect

```bash
cat <<'NOTE'
[!] This is the containment action for a read. Work Query 3's attribute list.

    For every table read with select ALL_ATTRIBUTES:
      [ ] rotate any credential, token or key held in an attribute
      [ ] revoke sessions derived from anything stored there
      [ ] record personal data and business records as disclosed — they cannot be rotated

    Revoking the reader and tightening IAM change what happens NEXT. Neither affects what has
    already left, and treating them as containment is the most common error here.
NOTE
```

#### Step 4 — Decide whether this was a walk or a workload

Query 2's distinct-table count, the `select` values and the presence of `ListTables` settle it:

- **Several tables, `ALL_ATTRIBUTES`, enumeration first** — a walk. Rotate and treat as disclosure.
- **Several tables, `COUNT` only** — sizing. Nothing left; still worth explaining, because an
  application does not size tables it does not own.
- **One table, many scans** — an application or an export job. Close it and add the role to
  `known_readers`.

---

## 4. Eradication

### Remove Attacker Access

#### Scope `dynamodb:Scan` and `dynamodb:Query` per table

A role with either on `Resource: "*"` can read every table in the account. Scoped to its own table
ARN it cannot, and that single change converts a compromised task role from an estate-wide read into
a single-table one. It is the highest-value item here and it is commonly wrong because
`Resource: "*"` is the path of least resistance when the first task policy is written.

#### Stop storing rotatable secrets in table items

Anything in an item is exposed by a single successful scan. Tokens and credentials belong in Secrets
Manager or Parameter Store, referenced by the item rather than embedded in it — which makes a
successful read worth much less.

#### Turn on data events for tables holding regulated data

Without them this incident is unobservable, and "was this table read" has no answer at all. The cost
remedy is documented and should be applied at the same time.

#### Deny estate-wide reads outside the application path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyDynamoDBEnumerationOutsideApplications",
  "Effect": "Deny",
  "Action": ["dynamodb:ListTables"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourApplicationRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the application. This denies **enumeration** rather than reading: an application
reads the table it was configured with and never needs to list tables, so the cost is close to zero
and it removes the reconnaissance half of the technique.

---

## 5. Recovery

### Restore Clean State

#### Verify the reader's access is gone and scoped

```bash
PRINCIPAL="${1:?principal ARN}"

case "$PRINCIPAL" in
  *:user/*)
    U="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')"
    A="$(aws iam list-access-keys --user-name "$U" \
          --query 'length(AccessKeyMetadata[?Status==`Active`])' --output text 2>/dev/null)"
    [ "${A:-0}" -eq 0 ] && echo "[OK] no active keys for $U" || echo "[FAIL] $U has $A active key(s)"
    ;;
  *:assumed-role/*)
    R="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $1}')"
    aws iam list-role-policies --role-name "$R" --query 'PolicyNames' --output text 2>/dev/null \
    | tr '\t' '\n' | grep -q 'RevokeOlderSessions' \
      && echo "[OK] session revocation policy attached to $R" \
      || echo "[FAIL] no RevokeOlderSessions policy — sessions from before containment are valid"
    ;;
esac
```

#### Verify rotation completed

```bash
cat <<'NOTE'
[!] No AWS API answers this. Confirm against the attribute list from §3 Step 3:

      [ ] every credential or token held in a read table has been rotated at its issuer
      [ ] sessions derived from that material have been revoked
      [ ] personal data and business records that cannot be rotated are recorded as disclosed
      [ ] the application no longer writes rotatable secrets into item attributes

    The last box is the one that prevents a repeat. Rotating a token and continuing to store the
    new one in the same attribute returns the estate to the same exposure with a different value.
NOTE
```

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"

# Exercise BREADTH with COUNT-only scans: they read the tables but return no item data, so this
# test moves nothing while still producing the events the correlation counts.
COUNT=0
for T in $(aws dynamodb list-tables --region "$REGION" --query 'TableNames[0:3]' --output text 2>/dev/null); do
  [ -z "$T" ] && continue
  aws dynamodb scan --table-name "$T" --region "$REGION" --select COUNT >/dev/null 2>&1 \
    && COUNT=$((COUNT + 1))
done
echo "[OK] $COUNT distinct tables scanned with select COUNT — expect the BREADTH correlation"
echo "[!] These returned no item data. If the single-event rule fires as well, its `select` gate is"
echo "    not deployed and it will alert on every sizing job in the estate."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Were data events enabled? | If not, the read is unobservable and the honest finding is that it cannot be assessed. |
| How many distinct tables, versus how many scans? | Breadth separates a walk from a workload; scan count does not. |
| What was `select`? | A COUNT scan moved nothing. Escalating one is how the rule family loses credibility. |
| Did `ListTables` precede the reads? | An application does not enumerate. |
| Did the role hold `dynamodb:Scan` on `Resource: "*"`? | Estate-wide read is what turns one compromised role into a walk. |
| What do the items contain? | The scope of the disclosure, and DynamoDB cannot tell you — it is schemaless beyond the keys. |

### Recommended Guardrails

**Scope `Scan` and `Query` per table.** One IAM change turns an estate-wide read into a single-table
one, and `Resource: "*"` is the common default.

**Count distinct tables, not scans.** It is the only measure that separates the technique from
ordinary traffic without tuning.

**Gate on `select`.** A COUNT scan cannot be exfiltration, and the field is free.

**Deny `ListTables` outside application roles.** Applications never need it, and it is the
reconnaissance half.

**Stop storing rotatable secrets in items.** It reduces impact rather than likelihood, which is the
only lever that helps once a read has already happened.

### Technique Reference

**T1530 — Data from Cloud Storage.** Verified live at https://attack.mitre.org/techniques/T1530/ on
2026-08-30. Reading stored data out of a managed data store is what this technique names.

The source rule maps to **`T1596 — Search Open Technical Databases`**, a **Reconnaissance** technique
covering WHOIS, passive DNS, CDN data and public scan databases — sources the adversary does not own.
Scanning your own table is not that, and this is one of the two least defensible mappings in the
source set alongside `T1505` on the item rules.

AWS references relied on throughout, all verified 2026-08-30:

- DynamoDB CloudTrail logging — the control/data plane split and the PartiQL coverage statement:
  https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
- `Scan` API reference — the `select` parameter and its values:
  https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Scan.html

Service-wide verified behaviour shared by every `dynamodb.*` playbook is in
`../_ground-truth/dynamodb.md`.

### Residual Risk

**Without data events the technique is unobservable.** Not poorly detected — invisible. Every rule
here depends on a paid setting, and an estate that declines it has no coverage of DynamoDB reads at
all. That is a legitimate cost decision and it should be recorded as an accepted risk rather than
assumed away.

**A legitimate export job is behaviourally identical.** Reading many tables with `ALL_ATTRIBUTES` is
what a backup or analytics pipeline does. Only the `known_readers` list separates them, and an estate
without one will close this alert as a batch job every time.

**The read cannot be undone.** Containment is rotation, and anything not rotatable — personal data,
business records — is disclosed permanently.

**DynamoDB cannot tell you what was taken.** It is schemaless beyond the key attributes, so the
scope of the disclosure is an application question. `ItemCount` is approximate and updates roughly
every six hours, so it indicates scale rather than counting what left.
