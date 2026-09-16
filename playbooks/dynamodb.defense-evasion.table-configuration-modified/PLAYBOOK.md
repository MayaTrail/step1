# IR Playbook: DynamoDB Table Configuration Modified — Streams disabled via `UpdateTable`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence evasion — a table's stream is disabled, removing the record of what items held before they changed, or its encryption configuration is altered |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High for Streams disabled or an encryption change; medium for a sequence of configuration changes. The source rule rates every `UpdateTable` identically. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002; T1600 |
| Services in Scope | DynamoDB, DynamoDB Streams, KMS, CloudTrail |

**What the technique does:** the actor changes table configuration. `UpdateTable` alters seven
different things and two of them reduce what can be reconstructed afterwards:

| Setting | Effect |
|---|---|
| `StreamSpecification.StreamEnabled` → false | The change record for every future item write is gone |
| `SSESpecification` changed | Who can read the table at rest changes — while it stays "encrypted" |

**Streams is the consequential one.** CloudTrail records that `UpdateItem` happened; it never records
what the item held before. Streams with `OLD_IMAGE` or `NEW_AND_OLD_IMAGES` is frequently the only
source of previous values.

**Why the usual reflexes miss it.** The first is the rule's name — *Multiple Update Operation
Performed* matches `UpdateTable`, not `UpdateItem`, so a reviewer believes item updates are covered
twice when they are covered once. The second is treating all seven settings alike: a throughput
adjustment and a stream being switched off arrive as the same alert. The third is assuming the stream
held previous values at all — a `KEYS_ONLY` stream never did. The fourth is reading an encryption
change as a weakening; the event does not carry direction.

**Detection thesis:** rate on which setting changed, treat Streams as a log rather than a feature,
and keep the autoscaling exclusion the source rule already gets right.

**Adjacent playbooks.** Item writes and deletions, and deletion protection, are
`../dynamodb.impact.table-items-modified-or-destroyed/`. Reads are
`../dynamodb.collection.table-scanned/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `UpdateTable` is control-plane and logged by default,
so this playbook works without DynamoDB data events — unlike three of the five rules in this source
set.

**DynamoDB Streams with `NEW_AND_OLD_IMAGES` on tables where item history matters.** This is the
prerequisite that decides whether a future data-manipulation incident is reconstructable. The view
type is chosen when the stream is created and cannot be changed retroactively for records already
written.

**A stream consumer that persists records beyond 24 hours.** The stream's own retention is one day,
which is shorter than most investigations — a Lambda writing to S3 or a Kinesis Data Firehose
delivery turns a 24-hour buffer into an archive.

A recorded encryption posture per table: which key, customer-managed or AWS-owned.

**Alerting (must be pre-configured)**

- **`UpdateTable` setting `StreamEnabled` false, excluding autoscaling → P0**
- **Streams disabled and deletion protection removed by the same principal → P0**
- **`UpdateTable` by a principal outside the provisioning path → P2**

**Response Tooling**

An IAM principal that can call `dynamodb update-table`, `describe-table` and
`describe-continuous-backups` outside the change pipeline.

**Known IOC Baselines**

The roles that own table configuration. Note that Application Auto Scaling is excluded by user agent
rather than by role, which is more robust — it does not depend on the scaling role's name.

The stream view type per table, recorded. Whether disabling a stream mattered depends entirely on
what it was configured to carry.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `UpdateTable` setting `StreamEnabled` false, excluding Application Auto Scaling | CloudTrail | T1685.002 |
| P0 | Streams disabled and deletion protection removed by the same principal | CloudTrail | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `UpdateTable` changing `SSESpecification` — direction is not in the event | CloudTrail | T1600 |
| P2 | Five or more `UpdateTable` calls by one principal in ten minutes, excluding autoscaling | Correlation rule | T1685.002 |
| P2 | `UpdateTable` by a principal outside the provisioning path, any setting | CloudTrail | T1685.002 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Named *Multiple Update Operation Performed*, matches `UpdateTable` | `UpdateTable` is control-plane and unrelated to `UpdateItem`. A reviewer reading the rule list concludes item updates are covered twice; they are covered once | Renamed to what it detects, and the item rules are cross-referenced explicitly |
| No content check on a call that changes seven things | A throughput adjustment and a stream being switched off arrive as the same alert. The two settings that reduce reconstructability are indistinguishable from operational tuning | Separate rules for Streams and for encryption, rated by effect |
| Streams not recognised as a record | CloudTrail never carries previous item values. Streams is frequently the only source, so disabling it is removing the log — not changing a feature | `T1685.002`, and the Streams rule ships at high |
| MITRE `T1505 — Server Software Component` | A Persistence technique about web shells and server modules. It is the same wrong mapping the item rules carry | `T1685.002` for Streams, `T1600` for encryption |
| Rated P4 | Removing the only record of previous item values, immediately before or after modifying them, is not a P4 | High |

**What the source rule gets right, and it is the only instance in this source set:** it excludes
`userAgent:autoscaling.amazonaws.com`. Application Auto Scaling calls `UpdateTable` continuously on
any table with provisioned capacity and scaling policies. Without that exclusion the rule would be
pure noise, and the exclusion is by **user agent** rather than by role — which is more robust,
because it does not depend on the scaling role's name. It is kept unchanged.

**Recommended detection — split by setting, with the autoscaling exclusion retained.**

```yaml
# DynamoDB table configuration modified (T1685.002)
#
# THE RULE'S NAME AND ITS LOGIC DESCRIBE DIFFERENT THINGS. It is called "Multiple Update Operation
# Performed" and it matches `UpdateTable` — a CONTROL-PLANE call that changes throughput, indexes,
# stream settings, encryption and deletion protection. It has nothing to do with `UpdateItem`, the
# data-plane operation its name suggests. A reviewer scanning the rule list would reasonably believe
# item updates were covered twice; they are covered once, in
# ../../dynamodb.impact.table-items-modified-or-destroyed/.
#
# IT HAS NO CONTENT CHECK ON A CALL THAT CHANGES SEVEN DIFFERENT THINGS, and rates all of them
# identically. The two that matter for a defender are:
#   StreamSpecification.StreamEnabled -> false   removes the change record for every future item
#                                                write, which is frequently the ONLY record of what
#                                                an item held before it was modified
#   SSESpecification changed                     alters who can read the table at rest
# A throughput adjustment and a stream being switched off arrive as the same alert.
#
# WHAT IT GETS RIGHT, AND IT IS WORTH RECORDING: it excludes `userAgent:autoscaling.amazonaws.com`.
# Application Auto Scaling calls UpdateTable continuously to adjust provisioned capacity, and without
# that exclusion the rule would be pure noise. That is a considered filter, and it is the only one of
# its kind in this source set.
#
# `UpdateTable` IS CONTROL-PLANE AND LOGGED BY DEFAULT. Unlike three of the five DynamoDB source
# rules, this one works without buying data events — which is exactly why disabling Streams through
# it is so quiet: the act is logged, and the consequence is that item history stops being recorded.
title: DynamoDB Streams disabled on a table
id: 4b0e9c17-52fa-4d83-91b6-0725ed84c3fa
name: dynamodb_streams_disabled
status: experimental
description: >-
  UpdateTable set StreamEnabled to false. DynamoDB Streams is frequently the only record of what an
  item held BEFORE it was modified — CloudTrail records that UpdateItem happened, never the previous
  values. Turning it off removes that record for every future write, and it does so through a call
  the source rule rates the same as a throughput change.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  # Three keys ANDed, and they do co-occur on a single event: an UpdateTable record carries
  # eventSource, eventName and the submitted stream specification together.
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'UpdateTable'
    requestParameters.streamSpecification.streamEnabled: false
  success:
    errorCode: null
  # Application Auto Scaling calls UpdateTable continuously. The source rule's exclusion of this
  # user agent is correct and is kept.
  autoscaling:
    userAgent|contains: 'autoscaling.amazonaws.com'
  condition: selection and success and not autoscaling
falsepositives:
  - >-
    A table whose stream consumer was decommissioned, where disabling the stream is tidy-up. It
    should follow the consumer's removal; disabling a stream that something is still reading is the
    shape worth questioning.
level: high
---
title: DynamoDB table encryption configuration changed
id: e39d5407-1cb8-4a26-b0f4-97e2013da8b5
name: dynamodb_table_encryption_changed
status: experimental
description: >-
  UpdateTable changed the server-side encryption specification. Moving from a customer-managed KMS
  key to an AWS-owned key removes the customer's ability to revoke access by disabling the key, and
  removes the KMS grant trail that shows who decrypted. The table stays encrypted throughout, so a
  configuration review reports it as compliant.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
  - https://attack.mitre.org/techniques/T1600/
tags:
  - attack.defense-evasion
  - attack.t1600
logsource:
  product: aws
  service: cloudtrail
detection:
  # Three keys ANDed, and they do co-occur on a single event: an UpdateTable record carries
  # eventSource, eventName and the submitted encryption specification together.
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'UpdateTable'
    requestParameters.sSESpecification|exists: true
  success:
    errorCode: null
  autoscaling:
    userAgent|contains: 'autoscaling.amazonaws.com'
  condition: selection and success and not autoscaling
falsepositives:
  - >-
    A migration onto a customer-managed key, which is the improving direction and produces the same
    event. The playbook reads which direction it went; the rule cannot.
level: high
---
title: DynamoDB table configuration changed repeatedly by one principal
id: 71a4c6e8-30bd-4915-8e7f-c250b93da746
status: experimental
description: >-
  One principal made five or more table configuration changes within ten minutes, excluding
  autoscaling. Any single change has an innocent reading; a sequence of them by one identity is
  someone working through the configuration, which is the shape the source rule was reaching for
  with its threshold and could not express because it counted every UpdateTable equally.
references:
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
correlation:
  type: event_count
  rules:
    - dynamodb_table_config_changed
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 5
falsepositives:
  - >-
    A deployment applying configuration across a table set in one run. Allowlist the pipeline role on
    the base rule rather than raising the threshold.
level: medium
---
title: DynamoDB table configuration changed
id: 2c8b47f0-d951-4e63-a17c-680fe32b9d54
name: dynamodb_table_config_changed
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful UpdateTable that
  is not Application Auto Scaling adjusting capacity. Control-plane, logged by default.
references:
  - https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'dynamodb.amazonaws.com'
    eventName: 'UpdateTable'
  success:
    errorCode: null
  autoscaling:
    userAgent|contains: 'autoscaling.amazonaws.com'
  condition: selection and success and not autoscaling
level: informational
```

What this set structurally cannot do: tell you which direction an encryption change went. The event
carries the new specification and not the old one, so §2 Query 2 reads the history for it.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> DynamoDB is **regional**. `UpdateTable` is control-plane and logged by default, so these queries
> work without data events.

Run Query 1 first; it establishes which of the seven settings changed.

#### Query 1 — Reconstruct: which setting, and was autoscaling responsible

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateTable \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r '.Events[].CloudTrailEvent | fromjson
    | select(.errorCode == null)
    # Application Auto Scaling calls UpdateTable continuously. Excluding it by USER AGENT rather
    # than by role is more robust — it does not depend on the scaling role being named predictably.
    | select((.userAgent // "") | test("autoscaling\\.amazonaws\\.com") | not)
    | (.requestParameters | tostring) as $rp
    | [ (if ($rp | test("\"streamEnabled\":\\s*false")) then "STREAMS-OFF" else empty end),
        (if ($rp | test("\"streamEnabled\":\\s*true")) then "streams-on" else empty end),
        (if ($rp | test("[sS]SESpecification")) then "ENCRYPTION" else empty end),
        (if ($rp | test("\"deletionProtectionEnabled\":\\s*false")) then "PROTECTION-OFF" else empty end),
        (if ($rp | test("globalSecondaryIndexUpdates")) then "index" else empty end),
        (if ($rp | test("provisionedThroughput")) then "throughput" else empty end) ] as $fields
    | "\(.eventTime)  table=\(.requestParameters.tableName // "-")  changed=[\($fields | join(","))]  " +
      "by=\(.userIdentity.arn)  agent=\((.userAgent // "-")[0:40])"' | sort
```

A row whose `changed=` list is only `throughput` or `index` is operational. `STREAMS-OFF` is the
finding. `ENCRYPTION` needs Query 2 to establish direction, because the event carries only the new
value.

#### Query 2 — What the stream was configured to carry, and what the key is now

```bash
TABLE="${1:?table name from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== Stream configuration ==="
aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" --output json 2>/dev/null \
| jq -r '"  streamEnabled: \(.Table.StreamSpecification.StreamEnabled // false)",
         "  viewType:      \(.Table.StreamSpecification.StreamViewType // "none")",
         "  latestStream:  \(.Table.LatestStreamArn // "none")"'

cat <<'NOTE'

[!] The VIEW TYPE decides whether disabling the stream mattered:
      NEW_AND_OLD_IMAGES / OLD_IMAGE  -> it carried previous values. Losing it is losing the only
                                         record of what items held before they changed.
      NEW_IMAGE / KEYS_ONLY           -> it never carried previous values. Disabling it removed
                                         nothing that would have helped a manipulation investigation.
    The view type is fixed when the stream is created and cannot be changed for records already
    written, so this was decided long before the incident.
NOTE

echo "=== Encryption now ==="
aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" --output json 2>/dev/null \
| jq -r '"  sseType:    \(.Table.SSEDescription.SSEType // "AWS owned key (default)")",
         "  kmsKeyArn:  \(.Table.SSEDescription.KMSMasterKeyArn // "none")",
         "  status:     \(.Table.SSEDescription.Status // "n/a")"'

echo "[!] The event carries the NEW specification only. To establish direction, read the previous"
echo "    UpdateTable or CreateTable for this table in Query 1's output."
```

#### Query 3 — Is there a consumer that persisted the stream beyond 24 hours

```bash
TABLE="${1:?table name}"
REGION="${AWS_REGION:-us-east-1}"

STREAM="$(aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" \
           --query 'Table.LatestStreamArn' --output text 2>/dev/null)"
echo "Stream ARN: ${STREAM:-none}"

if [ -n "$STREAM" ] && [ "$STREAM" != "None" ]; then
  echo "=== Lambda event source mappings reading this stream ==="
  aws lambda list-event-source-mappings --event-source-arn "$STREAM" --region "$REGION" \
    --query 'EventSourceMappings[].[UUID,FunctionArn,State]' --output text 2>/dev/null | sed 's/^/  /' \
    || echo "  (none)"
fi

cat <<'NOTE'

[!] DynamoDB Streams retains records for 24 HOURS. That is shorter than most investigations, so the
    question is whether a consumer archived them — a Lambda writing to S3, or a Kinesis delivery
    stream. If one exists, previous item values may survive the stream being disabled. If not, the
    24-hour window is all there ever was, and disabling the stream matters mainly going forward.
NOTE
```

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

Look for `UpdateContinuousBackups` and `UpdateTimeToLive` around the change. Streams disabled, PITR
disabled and TTL configured by one principal is the complete preparation for unrecoverable item
manipulation — and all three are control-plane, so all three are visible.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Re-enable the stream first. It is one call, and every item write until it is back has no previous-value
record — but note that re-enabling creates a **new** stream and does not recover the old one.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 4 shows Streams
disabled alongside PITR disabled or TTL configured, this is preparation for item manipulation that
cannot be reconstructed or restored. Go to
`../dynamodb.impact.table-items-modified-or-destroyed/` and re-enable recovery there first — that
one has a hard deadline and this one does not.

#### Step 1 — Re-enable the stream

```bash
TABLE="${1:?table name}"
REGION="${AWS_REGION:-us-east-1}"
VIEW="${2:-NEW_AND_OLD_IMAGES}"

echo "[!] Re-enabling creates a NEW stream with a new ARN. The previous stream's records are not"
echo "    recovered, and any consumer will need to be repointed at the new ARN."

aws dynamodb update-table --table-name "$TABLE" --region "$REGION" \
  --stream-specification "StreamEnabled=true,StreamViewType=${VIEW}" \
  && echo "[OK] stream re-enabled on $TABLE with view type $VIEW"

aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" \
  --query 'Table.{stream:StreamSpecification,arn:LatestStreamArn}' --output json 2>/dev/null
```

`NEW_AND_OLD_IMAGES` is the default here deliberately: it is the only view type that carries previous
values, and the incident that brought you to this playbook is precisely the one where those matter.

#### Step 2 — Repoint the stream consumer

```bash
TABLE="${1:?table name}"
REGION="${AWS_REGION:-us-east-1}"

NEW_ARN="$(aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" \
            --query 'Table.LatestStreamArn' --output text 2>/dev/null)"
echo "New stream ARN: $NEW_ARN"
echo "[!] Any Lambda event source mapping pointed at the OLD stream is now orphaned and silently"
echo "    processing nothing. Recreate it against the new ARN:"
echo "    aws lambda create-event-source-mapping --event-source-arn $NEW_ARN \\"
echo "      --function-name <fn> --starting-position LATEST --region $REGION"

aws lambda list-event-source-mappings --region "$REGION" --output json 2>/dev/null \
| jq -r --arg t "$TABLE" '.EventSourceMappings[]
    | select((.EventSourceArn // "") | contains($t))
    | "  \(.UUID)  \(.State)  \(.EventSourceArn)"'
```

This step is the one most likely to be missed. A stream re-enabled with an orphaned consumer looks
correct in `describe-table` and delivers nothing.

#### Step 3 — Contain the principal

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

#### Step 4 — Establish what happened during the gap

Between the stream being disabled and Step 1, every item write has no previous-value record. If item
data events were enabled, CloudTrail shows *that* writes happened and never what they replaced; if
they were not, even that is absent. The honest position for that window is that item modifications
are unreconstructable, and the report should say so rather than implying the data is intact.

---

## 4. Eradication

### Remove Attacker Access

#### Set the stream view type deliberately, everywhere it matters

`KEYS_ONLY` and `NEW_IMAGE` streams never carry previous values, so a table using them has no
manipulation-recovery capability regardless of whether the stream is enabled. That is a decision made
at creation and it is worth auditing independently of this incident.

#### Archive the stream beyond 24 hours

DynamoDB Streams retains records for one day, which is shorter than most investigations. A consumer
that persists them — a Lambda to S3, or Kinesis Data Firehose — is what turns a buffer into evidence.

#### Deny configuration changes outside the provisioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyDynamoDBConfigurationChanges",
  "Effect": "Deny",
  "Action": ["dynamodb:UpdateTable", "dynamodb:UpdateContinuousBackups",
             "dynamodb:UpdateTimeToLive"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. **Note this will break Application Auto Scaling**, which calls
`UpdateTable` under a service-linked role: add that role to the exception list, or scope the denial
with a condition on the request rather than on the principal. Test in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify streams are enabled with a view type that carries previous values

```bash
REGION="${AWS_REGION:-us-east-1}"

aws dynamodb list-tables --region "$REGION" --query 'TableNames[]' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    aws dynamodb describe-table --table-name "$T" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg t "$T" '
        (.Table.StreamSpecification.StreamEnabled // false) as $on
        | (.Table.StreamSpecification.StreamViewType // "none") as $v
        | if ($on and ($v == "NEW_AND_OLD_IMAGES" or $v == "OLD_IMAGE")) then "[OK] \($t)  \($v)"
          elif $on then "[!] \($t)  \($v) — enabled but carries NO previous values"
          else "[FAIL] \($t) — stream disabled" end'
  done
```

The middle case is the one worth acting on. A stream that is enabled but configured `KEYS_ONLY`
satisfies any check that asks "is the stream on" and provides nothing a manipulation investigation
can use.

#### Verify the consumer is attached to the current stream

```bash
TABLE="${1:?table name}"
REGION="${AWS_REGION:-us-east-1}"

ARN="$(aws dynamodb describe-table --table-name "$TABLE" --region "$REGION" \
        --query 'Table.LatestStreamArn' --output text 2>/dev/null)"
N="$(aws lambda list-event-source-mappings --event-source-arn "$ARN" --region "$REGION" \
      --query 'length(EventSourceMappings[?State==`Enabled`])' --output text 2>/dev/null)"
[ "${N:-0}" -gt 0 ] && echo "[OK] $N enabled consumer(s) on the current stream" \
                    || echo "[FAIL] no enabled consumer on $ARN — records are buffered for 24h and then lost"
```

#### Confirm the corrected detection fires

```bash
TABLE="${1:?a NON-PRODUCTION table name}"
REGION="${AWS_REGION:-us-east-1}"

# Exercise a THROUGHPUT change first — it must NOT produce a high-severity alert. Then re-state the
# stream specification, which must. If both produce the same output, the content check is not
# deployed and the rule is still the source pack's occurrence counter.
aws dynamodb update-table --table-name "$TABLE" --region "$REGION" \
  --billing-mode PAY_PER_REQUEST >/dev/null 2>&1 \
  && echo "[OK] billing mode changed — expect NO high-severity alert"

sleep 30
aws dynamodb update-table --table-name "$TABLE" --region "$REGION" \
  --stream-specification 'StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES' >/dev/null 2>&1 \
  && echo "[OK] stream specification restated — expect the stream rule to evaluate it"
echo "[!] This ENABLES a stream rather than disabling one, so nothing is lost by the test. If your"
echo "    deployment alerts on this, the rule is matching the field rather than the value false."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Which of the seven settings changed? | The whole triage. A throughput change and a stream being switched off are the same event and different incidents. |
| What was the stream's view type? | `KEYS_ONLY` or `NEW_IMAGE` never carried previous values, so disabling it removed nothing an investigation would have used. |
| Was a consumer archiving the stream beyond 24 hours? | Without one, the retention window is a day and the stream was never evidence to begin with. |
| Did the same principal also disable PITR or set TTL? | All three are control-plane and visible, and together they are complete preparation for unrecoverable manipulation. |
| Was the encryption change toward or away from a customer-managed key? | The event carries only the new value; direction comes from the previous event. |
| Was autoscaling excluded correctly? | Without the user-agent exclusion this rule is unusable, and it is the one thing the source got right. |

### Recommended Guardrails

**Set `NEW_AND_OLD_IMAGES` on tables where item history matters.** It is the only view type that
makes a manipulation incident reconstructable, and it is chosen at stream creation.

**Archive the stream.** A 24-hour buffer is shorter than most investigations; a consumer writing to
S3 turns it into evidence.

**Alert on the setting, not the call.** A rule that reports `UpdateTable` without reading the request
body cannot distinguish a capacity adjustment from removing the change record.

**Keep the autoscaling user-agent exclusion.** Excluding by user agent rather than by role is more
robust, and without it the rule is pure noise.

**Watch the three control-plane preparations together** — Streams off, PITR off, TTL set. Each is
individually explicable and the combination is not.

### Technique Reference

**T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log.** Verified live at
https://attack.mitre.org/techniques/T1685/002/ on 2026-08-30. DynamoDB Streams is the change record
for item writes, and disabling it is removing the log of what happened.

**T1600 — Weaken Encryption** covers the `SSESpecification` change. Verified live 2026-08-30.

`T1578.005 — Modify Cloud Compute Configurations` was considered and set aside: DynamoDB is a
managed data store rather than compute.

The source rule maps to **`T1505 — Server Software Component`** under Persistence — the same mapping
it applies to the item rules, and equally wrong.

AWS references relied on throughout, all verified 2026-08-30:

- DynamoDB CloudTrail logging — the control-plane list confirming `UpdateTable` is logged by default:
  https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
- `UpdateTable` API reference — the settable fields:
  https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html

Service-wide verified behaviour shared by every `dynamodb.*` playbook is in
`../_ground-truth/dynamodb.md`.

### Residual Risk

**Re-enabling a stream does not recover the old one.** It creates a new stream with a new ARN, the
previous records are gone, and any consumer is silently orphaned until repointed.

**A `KEYS_ONLY` stream provides nothing and passes every check.** "Is the stream enabled" is
satisfied; "can we reconstruct what changed" is not. The view type is the setting that matters and it
is rarely reviewed.

**The 24-hour retention is shorter than most investigations.** Without an archiving consumer, the
stream is a buffer rather than a record, and disabling it matters mainly going forward.

**Denying `UpdateTable` by SCP breaks Application Auto Scaling.** It calls the API under a
service-linked role, so a principal-scoped denial takes capacity management with it — the guardrail
has a real operational cost that has to be planned for rather than discovered.
