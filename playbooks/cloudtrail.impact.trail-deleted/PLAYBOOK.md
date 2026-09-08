# IR Playbook: CloudTrail Trail Deleted — audit coverage removed via `DeleteTrail`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence evasion — a trail is removed, ending future coverage and destroying its configuration, while leaving the already-delivered log files intact |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical for a multi-Region or organization trail; high for a single-Region one. The source rule rates it P2, the same as stopping a trail, although the two differ in both directions. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | CloudTrail, S3, CloudWatch Logs, IAM, AWS Organizations |

**What the technique does:** the actor calls `DeleteTrail`. Two things are true at once and they
pull in opposite directions.

> *"While deleting a CloudTrail trail is an irreversible action, CloudTrail does not delete log
> files in the Amazon S3 bucket for that trail, the Amazon S3 bucket itself, or the CloudWatch log
> group to which the trail delivers events."*

So the **historical record survives** — everything delivered before the deletion is still in the
bucket and still searchable. What is destroyed is **future coverage** and the **trail's
configuration**, and the configuration exists nowhere except the last `CreateTrail` or `UpdateTrail`
event, which `lookup-events` serves for ninety days.

**Why the usual reflexes miss it.** The first is to assume the logs are gone: they are not, and a
response that opens on that assumption skips a reconstruction that is entirely possible. The second
is to rate it alongside `StopLogging`: a stop is undone with one call, while a deletion requires
rebuilding a configuration that has a recovery deadline. The third is to filter on success — AWS
refuses this call outside the trail's home Region, so an actor guessing fails first. The fourth is
to confirm recovery by checking that a trail exists: delete-and-replace leaves a trail with the same
name and different selectors, and every existence check passes.

**Detection thesis:** recover the configuration first because it is the only thing on a clock,
establish blast radius from the trail's history rather than from the event, and treat
delete-then-create as its own finding.

**Adjacent playbooks.** The trail paused rather than removed is
`../cloudtrail.stealth.trail-logging-stopped/`. Selectors narrowed while logging continues is
`../cloudtrail.stealth.trail-modified/`. The downstream symptom is
`../cloudtrail.stealth.no-logs-received/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

**A copy of every trail's configuration outside AWS** — in the IaC definition, or a scheduled
`describe-trails` export. This is the highest-value item in this playbook and the cheapest. Without
it, recovering a deleted trail depends entirely on a CloudTrail event with a ninety-day life; with
it, the deadline disappears.

An **organization trail owned by the management account**. Member accounts cannot delete one
regardless of their IAM permissions, so the technique produces a refused attempt rather than a gap.

CloudTrail history retained **beyond** the 90-day `lookup-events` horizon, in the trail's own S3
bucket with a lifecycle policy that is a deliberate decision rather than a default.

Knowledge of where each trail delivers. Because the bucket survives the deletion, that bucket is
where the entire pre-deletion record still lives — and after the trail is gone, nothing in the
CloudTrail console points at it.

**Alerting (must be pre-configured)**

- **`DeleteTrail` succeeds on a multi-Region or organization trail → P0**
- **`DeleteTrail` succeeds and `CreateTrail` follows from the same principal within 1h — a replacement whose selectors nobody has compared → P0**
- **`DeleteTrail` refused with `InvalidHomeRegionException` — the caller was guessing which Region owns the trail → P0**

**Response Tooling**

An IAM principal that can call `cloudtrail create-trail`, `describe-trails`, `get-trail-status` and
`lookup-events` **in every Region**, outside the change pipeline.

Read access to the destination bucket of every trail, independent of CloudTrail — after a deletion,
the bucket is the evidence and nothing in CloudTrail references it any more.

**Known IOC Baselines**

The roles that legitimately manage CloudTrail. In most estates this is the deployment pipeline and
nothing else, which makes any other principal a finding rather than a question.

The teardown schedule for non-production environments, which is the only routine explanation for a
trail deletion and is easy to confirm or exclude in one step.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `DeleteTrail` succeeds on a trail whose last configuration shows `isMultiRegionTrail` or `isOrganizationTrail` true | CloudTrail join | T1685.002 |
| P0 | `DeleteTrail` succeeds and `CreateTrail` follows from the same principal within 1h | Correlation rule | T1685.002 |
| P0 | `DeleteTrail` refused with `InvalidHomeRegionException` — AWS accepts this call only in the home Region and never on a shadow trail | CloudTrail | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `DeleteTrail` succeeds on a single-Region trail — logging stops in that Region only | CloudTrail join | T1685.002 |
| P2 | `DeleteTrail` succeeds and no `CreateTrail`/`UpdateTrail` for that trail exists in the retention window — the configuration is unrecoverable | CloudTrail join | T1685.002 |
| P2 | `DeleteTrail` refused with `NotOrganizationMasterAccountException` — a member account probing an organization trail | CloudTrail | T1685.002 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Reports the deletion and nothing about what survived | A responder will reasonably assume the log history is gone. AWS states it is not — the files, the bucket and the log group all remain — so the assumption costs the hour in which the surviving record is most useful | Stated in the rule description, the query and §3 Step 1, so it reaches the responder in whatever they read first |
| Rated P2, identical to `StopLogging` | The two differ in both directions. A stop is undone with one call; a deletion destroys a configuration that exists only in a 90-day event window. Equal rating hides the deadline | Critical for multi-Region and organization trails, high for single-Region, with the recovery deadline surfaced |
| No blast-radius dimension | *"Deleting a multi-Region trail will stop logging of events in all AWS Regions... Deleting a single-Region trail will stop logging of events in that Region only."* One event name, two very different incidents, and the distinguishing field is not in the event | Joined to the trail's last create or update event, which carries `isMultiRegionTrail` and `isOrganizationTrail` |
| `NOT _exists_:errorCode` drops every refused attempt | AWS refuses this outside the home Region and on shadow trails, so an actor guessing fails first — before coverage is lost | A second rule on the diagnostic error codes, at high |
| No pairing with `CreateTrail` | Delete-and-replace leaves `describe-trails` returning a trail with the same name and different selectors. Every existence check passes | A `temporal_ordered` correlation over 1h, grouped by principal |

**Recommended detection — the deletion, the refused attempt, and the replacement.**

```yaml
# CloudTrail trail deleted (T1685.002)
#
# THE DELIVERED LOG FILES SURVIVE. AWS: deleting a trail "does not delete log files in the Amazon S3
# bucket for that trail, the Amazon S3 bucket itself, or the CloudWatch log group". This destroys
# FUTURE coverage, not PAST evidence, and a responder who assumes otherwise loses the hour in which
# the surviving history is most useful.
#
# What IS irreversible is the configuration, which exists only in the last CreateTrail or UpdateTrail
# event — a 90-day window and the real deadline. Blast radius (isMultiRegionTrail) is likewise not in
# the event. Full rationale: detections/detection_note_t1685_002.md.
title: CloudTrail trail deleted
id: 2b7c40e9-6f13-4a58-9c02-d81e5b3a7f04
name: cloudtrail_trail_deleted
status: experimental
description: >-
  A successful DeleteTrail. Future coverage from this trail ends immediately, and the trail's
  configuration is gone irreversibly — it exists only in the last CreateTrail or UpdateTrail event.
  The already-delivered log files, the bucket and the CloudWatch log group are NOT deleted, so the
  historical record survives and remains fully searchable.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: 'DeleteTrail'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - >-
    A decommissioning that removes a trail alongside the account or workload it served. The
    surrounding teardown activity is the corroborating evidence, and a deletion with nothing around
    it is what makes this worth waking someone for.
level: critical
---
title: CloudTrail DeleteTrail attempted and refused
id: 8f1a63d7-c058-4e92-b346-70ad9e2c15b4
name: cloudtrail_trail_delete_refused
status: experimental
description: >-
  A DeleteTrail that failed. As with StopLogging, AWS accepts this call only in the trail's home
  Region and never on a shadow trail, so InvalidHomeRegion means the caller was guessing.
  NotOrganizationMasterAccount means a member account tried to remove an organization trail it
  cannot touch, and TrailNotFound means it was enumerating names. All three arrive before coverage
  is lost, and all three are dropped by any rule filtering on success.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: 'DeleteTrail'
  diagnostic_errors:
    errorCode:
      - 'InvalidHomeRegionException'
      - 'NotOrganizationMasterAccountException'
      - 'TrailNotFoundException'
      - 'AccessDenied'
      - 'InsufficientDependencyServiceAccessPermissionException'
  condition: selection and diagnostic_errors
falsepositives:
  - >-
    A cross-Region teardown loop that calls DeleteTrail everywhere and expects most calls to fail.
    A real and unfortunate pattern; allowlist the role rather than dropping the rule, because it is
    indistinguishable from an actor searching for the home Region.
level: high
---
title: CloudTrail trail deleted and replaced by the same principal
id: 4d90e2b8-53af-41c6-8e07-b2f491c6a3d5
status: experimental
description: >-
  A trail was deleted and a new one created by the same principal shortly after. This is the shape
  that survives review: describe-trails still returns a trail, often with the same name, so every
  check that asks "is there a trail" passes. What changed is what it captures — selectors, Regions,
  global service events — and none of that is visible without comparing the new configuration to the
  deleted one.
references:
  - https://attack.mitre.org/techniques/T1685/002/
  - https://attack.mitre.org/techniques/T1070/
tags:
  - attack.defense-evasion
  - attack.t1685.002
  - attack.t1070
correlation:
  type: temporal_ordered
  rules:
    - cloudtrail_trail_deleted
    - cloudtrail_trail_created
  group-by:
    - userIdentity.arn
  timespan: 1h
falsepositives:
  - >-
    A trail being recreated to change a setting that cannot be updated in place. Rare, and it should
    arrive with a change record; the comparison in the playbook resolves it in one step.
level: critical
---
title: CloudTrail trail created
id: 7e5b18ca-024d-4f31-a96b-3c08d7e51f62
name: cloudtrail_trail_created
status: experimental
description: >-
  Base rule — correlation component and change accounting, never for direct alerting. A successful
  CreateTrail. On its own this is a trail being set up, which is a good thing happening.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_CreateTrail.html
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName: 'CreateTrail'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: it cannot recover a trail whose last create or update event
has aged out of the retention window. Where that has happened, the trail can only be re-specified
from intent, and the report should say the previous configuration is unknown rather than implying it
was reproduced.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first. It is the recovery step and it is the only part of this playbook with a deadline.

#### Query 1 — Recover the deleted trail's configuration

```bash
TRAIL="${1:?trail name from the alert required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-90d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%SZ')"
OUT="./recovered-${TRAIL}-config.json"

# The DeleteTrail request carries only the name. Everything needed to rebuild the trail is in its
# last CreateTrail or UpdateTrail event, and nowhere else once the trail is gone.
for EVT in UpdateTrail CreateTrail; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg t "$TRAIL" '[.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null) | select(.requestParameters.name == $t)]
      | sort_by(.eventTime) | last
      | if . == null then empty else {at: .eventTime, by: .userIdentity.arn,
                                      config: .requestParameters} end'
done | jq -s 'sort_by(.at) | last' > "$OUT"

if [ -s "$OUT" ] && [ "$(jq -r 'if . == null then "null" else "ok" end' "$OUT")" = "ok" ]; then
  echo "[OK] recovered configuration -> $OUT"
  jq -r '.config | "  multiRegion=\(.isMultiRegionTrail)  globalEvents=\(.includeGlobalServiceEvents)",
                  "  orgTrail=\(.isOrganizationTrail)  validation=\(.enableLogFileValidation)",
                  "  bucket=\(.s3BucketName)  kms=\(.kmsKeyId // "none")"' "$OUT"
else
  echo "[FAIL] no CreateTrail or UpdateTrail for $TRAIL in the last 90 days."
  echo "       The configuration is UNRECOVERABLE from CloudTrail. Check the IaC repository."
  echo "       If it is not there either, the trail can only be re-specified from intent, and the"
  echo "       report must say the previous configuration is unknown."
fi
```

#### Query 2 — Find the surviving log files, because they are the evidence

```bash
CONFIG="${1:-./recovered-*-config.json}"
BUCKET="$(jq -r '.config.s3BucketName // empty' $CONFIG 2>/dev/null | head -1)"
PREFIX="$(jq -r '.config.s3KeyPrefix // empty' $CONFIG 2>/dev/null | head -1)"

if [ -z "$BUCKET" ]; then
  echo "[!] no bucket recovered — list candidates and identify by contents:"
  aws s3api list-buckets --query 'Buckets[?contains(Name, `cloudtrail`) || contains(Name, `logs`)].Name' \
    --output text 2>/dev/null | tr '\t' '\n'
  exit 0
fi

# AWS: deleting a trail "does not delete log files in the Amazon S3 bucket for that trail, the
# Amazon S3 bucket itself, or the CloudWatch log group". Everything before the deletion is here.
echo "=== Pre-deletion log files (these SURVIVED the deletion) ==="
aws s3 ls "s3://${BUCKET}/${PREFIX:+$PREFIX/}AWSLogs/" --recursive 2>/dev/null | tail -20 \
  || echo "[!] cannot list ${BUCKET} — check the bucket policy and that it still exists"

echo
echo "[OK] the historical record is intact and searchable. Query it with Athena or by download."
echo "     What was lost is coverage AFTER the deletion timestamp, not before it."
```

This is the query that corrects the assumption the alert creates. The bucket outlives the trail, and
after the deletion nothing in the CloudTrail console points at it any more — which is why the
recovered configuration is the route back to your own evidence.

#### Query 3 — Establish what coverage remains, and whether a replacement appeared

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

echo "=== Trails that exist now, everywhere ==="
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --include-shadow-trails --region "$R" --output json 2>/dev/null \
  | jq -r --arg r "$R" '.trailList[]
      | "\($r)  \(.Name)  org=\(.IsOrganizationTrail)  multiregion=\(.IsMultiRegionTrail)  " +
        "home=\(.HomeRegion)  globalevents=\(.IncludeGlobalServiceEvents)  validation=\(.LogFileValidationEnabled)"'
done | sort -u

echo
echo "=== Was a replacement created after the deletion? ==="
for EVT in DeleteTrail CreateTrail; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | "\(.eventTime)  \(.eventName)  \(.errorCode // "OK")  \(.userIdentity.arn)  " +
        "trail=\(.requestParameters.name // "-")  multiRegion=\(.requestParameters.isMultiRegionTrail // "-")"'
done | sort
```

Compare any `CreateTrail` here against Query 1's recovered configuration field by field. A
replacement with the same name and `multiRegion=false` where the original was true is the
delete-and-replace shape: `describe-trails` returns a trail, every existence check passes, and
coverage is a fraction of what it was.

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 3 required}"
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

Because the deleted trail stopped recording at the deletion, this session view is itself incomplete
after that timestamp unless another trail covered the account. Query 3's inventory says which case
you are in, and the answer determines how much of this output to trust.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Recovery of the configuration comes first, then restoring coverage, then the principal. The order is
driven by the deadline: the configuration is the only thing that expires.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 3 shows no trail
logging anywhere, the account is dark and the response itself is unrecorded. Create a replacement
trail immediately, from the recovered configuration if Query 1 succeeded and from the organisation
baseline if it did not, and note the unrecorded interval in the timeline.

#### Step 1 — Tell the responder what survived, before anything else

```bash
CONFIG="${1:-./recovered-*-config.json}"
BUCKET="$(jq -r '.config.s3BucketName // empty' $CONFIG 2>/dev/null | head -1)"

cat <<NOTE
[!] READ THIS BEFORE SCOPING THE INCIDENT

The deleted trail's log files were NOT deleted. AWS: deleting a trail "does not delete log files in
the Amazon S3 bucket for that trail, the Amazon S3 bucket itself, or the CloudWatch log group to
which the trail delivers events."

  Surviving evidence: s3://${BUCKET:-<run Query 1 to recover the bucket name>}

Everything up to the deletion timestamp is intact and searchable. The gap starts at the deletion and
ends when coverage is restored in Step 2. Scope the investigation to that interval, not to the whole
retention period.
NOTE
```

This step is deliberately not a command that changes anything. It exists because the most expensive
error available here is a false assumption in the first ten minutes, and the correction has to
arrive before the scoping decision rather than after it.

#### Step 2 — Restore coverage

```bash
CONFIG="${1:-./recovered-config.json}"
NEW_NAME="${2:?a name for the restored trail required}"
HOME_REGION="${3:-${AWS_REGION:-us-east-1}}"

if [ ! -s "$CONFIG" ]; then
  echo "[FAIL] no recovered configuration — run §2 Query 1 first, or rebuild from the IaC baseline"
  exit 1
fi

BUCKET="$(jq -r '.config.s3BucketName' "$CONFIG")"
MULTI="$(jq -r '.config.isMultiRegionTrail // "true"' "$CONFIG")"
GLOBAL="$(jq -r '.config.includeGlobalServiceEvents // "true"' "$CONFIG")"

# Multi-Region and global service events are restored to TRUE unless the recovered config says
# otherwise, because without them IAM and STS activity is not delivered to any trail outside
# us-east-1 — a gap that would otherwise be quietly reproduced.
aws cloudtrail create-trail --name "$NEW_NAME" --s3-bucket-name "$BUCKET" \
  $([ "$MULTI" = "true" ] && echo "--is-multi-region-trail") \
  $([ "$GLOBAL" = "false" ] || echo "--include-global-service-events") \
  --enable-log-file-validation --region "$HOME_REGION" \
  && aws cloudtrail start-logging --name "$NEW_NAME" --region "$HOME_REGION" \
  && echo "[OK] trail $NEW_NAME created and logging in $HOME_REGION"

aws cloudtrail get-trail-status --name "$NEW_NAME" --region "$HOME_REGION" \
  --query '{IsLogging:IsLogging,LatestDeliveryError:LatestDeliveryError}' --output json 2>/dev/null
```

Log file validation is enabled here even if the original did not have it. Restoring a trail is the
one moment when adding it costs nothing, and without it the new trail's files can be shown to exist
but not to be complete.

#### Step 3 — Compare any replacement trail against what was deleted

```bash
CONFIG="${1:-./recovered-config.json}"
SUSPECT="${2:?the name of the trail created after the deletion}"
REGION="${3:-${AWS_REGION:-us-east-1}}"

aws cloudtrail describe-trails --trail-name-list "$SUSPECT" --region "$REGION" --output json 2>/dev/null \
| jq -r --slurpfile old "$CONFIG" '.trailList[0] as $new
  | $old[0].config as $o
  | "multiRegion:   was \($o.isMultiRegionTrail // "?")  now \($new.IsMultiRegionTrail)",
    "globalEvents:  was \($o.includeGlobalServiceEvents // "?")  now \($new.IncludeGlobalServiceEvents)",
    "validation:    was \($o.enableLogFileValidation // "?")  now \($new.LogFileValidationEnabled)",
    "bucket:        was \($o.s3BucketName // "?")  now \($new.S3BucketName)"'

echo
echo "[!] Also compare the event selectors, which are set separately from the trail:"
aws cloudtrail get-event-selectors --trail-name "$SUSPECT" --region "$REGION" --output json 2>/dev/null
```

A replacement that matches on every line is a legitimate recreation. One that differs on
`multiRegion` or on its selectors is the delete-and-replace shape, and it is designed to pass exactly
the check that asks whether a trail exists.

#### Step 4 — Contain the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 3 required}"

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

As with stopping a trail, there is no operational workflow that legitimately deletes one outside the
deployment pipeline, so revoking this principal carries less risk of breaking something important
than it does in most playbooks.

---

## 4. Eradication

### Remove Attacker Access

#### Work the surviving history, which is most of it

The bucket from Query 2 holds everything delivered before the deletion. That is usually months of
data and it is the primary evidence for the investigation — including for establishing how the
principal obtained the permission in the first place. Query it directly with Athena or by download;
the CloudTrail console will not help, because the trail it belonged to no longer exists.

The gap is the interval from the deletion to Step 2's restoration, and only that interval needs
reconstructing from other sources: AWS Config configuration items, GuardDuty findings, VPC flow
logs, service-specific access logs.

#### Create the organization trail if there is not one

Member accounts cannot delete an organization trail regardless of their IAM permissions, so this
converts the technique from a success into a `NotOrganizationMasterAccountException`. It is the only
control here that prevents rather than detects.

#### Deny the operation outside a break-glass path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyCloudTrailTampering",
  "Effect": "Deny",
  "Action": ["cloudtrail:DeleteTrail", "cloudtrail:StopLogging",
             "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"],
  "Resource": "*",
  "Condition": {"ArnNotLike": {"aws:PrincipalARN": "arn:aws:iam::*:role/YourBreakGlassRole"}}
}
```

Attach it to an OU, not the management account, where SCPs do not apply. `YourBreakGlassRole` must
be a role that genuinely exists — an `ArnNotLike` against a non-existent role denies the action to
everyone including you. Test in a non-production OU first.

#### Put the trail configuration somewhere that does not expire

The whole difficulty of this incident is that the configuration lived only in a CloudTrail event
with a ninety-day life. A scheduled `describe-trails` export, or a trail defined in IaC, removes the
deadline entirely and turns recovery into a redeploy.

---

## 5. Recovery

### Restore Clean State

#### Verify coverage is genuinely restored, not merely present

```bash
EXPECT_MULTI="${1:-true}"

for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --region "$R" --query 'trailList[].TrailARN' --output text 2>/dev/null \
  | tr '\t' '\n' | while read -r T; do
      [ -z "$T" ] && continue
      aws cloudtrail get-trail-status --name "$T" --region "$R" --output json 2>/dev/null \
      | jq -r --arg t "$T" '
          if .IsLogging != true then "[FAIL] \($t) exists but is not logging"
          elif (.LatestDeliveryError // "") != "" then "[FAIL] \($t) logging but delivery failing: \(.LatestDeliveryError)"
          else "[OK] \($t) logging, last delivery \(.LatestDeliveryTime // "unknown")" end'
    done
done | sort -u

echo
aws cloudtrail describe-trails --include-shadow-trails --output json 2>/dev/null \
| jq -r 'if ([.trailList[] | select(.IsMultiRegionTrail == true and .IncludeGlobalServiceEvents == true)] | length) > 0
         then "[OK] a multi-Region trail with global events exists — IAM and STS are covered"
         else "[FAIL] no multi-Region trail with global events — IAM and STS activity is invisible" end'
```

"A trail exists" is not recovery, and it is precisely what a delete-and-replace is designed to
satisfy. The checks that matter are that it is logging, that delivery is succeeding, and that it is
multi-Region with global service events — without which IAM and STS calls reach no trail at all.

#### Verify the selectors match what was lost

```bash
TRAIL="${1:?restored trail name required}"
CONFIG="${2:-./recovered-config.json}"
REGION="${3:-${AWS_REGION:-us-east-1}}"

echo "=== Selectors on the restored trail ==="
aws cloudtrail get-event-selectors --trail-name "$TRAIL" --region "$REGION" --output json 2>/dev/null

echo
echo "[!] Compare against the recovered configuration. Selectors are set by a separate call"
echo "    (PutEventSelectors) and are NOT part of CreateTrail, so a trail restored from the"
echo "    recovered config alone will have DEFAULT selectors — management events only, no data"
echo "    events — even where the original captured more."
[ -s "$CONFIG" ] && jq -r '.config | "original bucket=\(.s3BucketName) multiRegion=\(.isMultiRegionTrail)"' "$CONFIG"
```

This is the step most likely to be skipped and the one that silently reproduces a gap. Data events
are configured separately and are off by default, so a faithfully restored *trail* can still be
capturing far less than the one it replaced.

#### Confirm the corrected detection fires

```bash
WRONG_REGION="${1:-eu-west-1}"
TRAIL="${2:?a NON-PRODUCTION trail name whose home Region is NOT $WRONG_REGION}"

# Exercise the REFUSED path. AWS refuses DeleteTrail outside the trail's home Region and on shadow
# trails, so this proves the detection without deleting anything at all.
aws cloudtrail delete-trail --name "$TRAIL" --region "$WRONG_REGION" 2>&1 \
  | grep -qi 'InvalidHomeRegion' \
  && echo "[OK] refused with InvalidHomeRegionException — expect the refused-attempt rule within 15 min" \
  || echo "[!] no InvalidHomeRegionException — confirm $WRONG_REGION is not the trail's home Region"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was the configuration recovered, and how close to the 90-day limit? | This is the only part of the incident with a deadline. If it was close, the missing export is the finding. |
| Was the trail multi-Region or an organization trail? | It is the difference between losing one Region and losing the account, and the event does not say. |
| Did the responder know the log files survived? | If the first hour was spent assuming the history was gone, the process failed even though the detection worked. |
| Was a replacement trail created, and do its selectors match? | Delete-and-replace passes every existence check. Only a field-by-field comparison catches it. |
| Was there an organization trail? | If yes, this was an attempt against an account trail and coverage continued. If no, that is the recommendation that matters most. |
| Did the restored trail get its data-event selectors back? | Selectors are a separate call and default to management events only, so a faithful-looking restoration can quietly reduce coverage. |

### Recommended Guardrails

**Export every trail's configuration on a schedule, outside AWS.** The cheapest item here and the
one that removes the deadline. Recovery becomes a redeploy instead of a race against a ninety-day
event horizon.

**Create a management-account organization trail.** Member accounts cannot delete one at all, so the
technique fails rather than succeeds. Everything else in this playbook is detection; this is
prevention.

**Say what survived in the alert text.** The single most expensive error available in this incident
is assuming the log history is gone. That correction belongs in the alert, not in a playbook someone
reads twenty minutes later.

**Alert on refused attempts.** The wrong-Region refusal is high fidelity, free, and arrives before
coverage is lost. It is also the only part of this technique that can be safely exercised as a
detection test.

**Compare replacements rather than counting trails.** Any check that asks "is there a trail" is
satisfied by a delete-and-replace. The check that works compares selectors and flags against the
previous configuration, which requires having kept it.

### Technique Reference

**T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log.** Verified live at
https://attack.mitre.org/techniques/T1685/002/ on 2026-08-30.

**T1070 — Indicator Removal** is tagged on the delete-and-replace correlation: a trail with the
original's name and reduced selectors is the expected state restored in appearance only. Verified
live 2026-08-30.

AWS references relied on throughout, all verified 2026-08-30:

- `DeleteTrail` API reference — the log-files-survive statement, the multi-Region versus
  single-Region blast radius, the home-Region constraint and the full error list:
  https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html
- CloudTrail concepts — organization trails and member-account permissions, and global service
  event handling: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html

Service-wide verified behaviour shared by every `cloudtrail.*` playbook is in
`../_ground-truth/cloudtrail.md`.

### Residual Risk

**A configuration older than the retention window is unrecoverable.** Beyond ninety days the trail
can only be re-specified from intent, and any claim that it was "restored" is then unverifiable. The
scheduled export is the only thing that removes this, and it has to be running before the incident.

**Selectors are not part of the trail and are easily lost in restoration.** `CreateTrail` does not
carry them; they are set by `PutEventSelectors` and default to management events only. A restoration
that looks complete can be capturing materially less than the trail it replaced, and nothing in the
trail's own status will show it.

**The bucket can be deleted separately.** The log files survive the trail's deletion, but nothing
protects them from a subsequent `DeleteObject` or a lifecycle rule. Object Lock or a bucket policy
denying deletion is what makes the surviving evidence actually durable, and neither is implied by
the trail existing.

**An account-level trail can be deleted even where an organization trail exists.** Coverage
continues through the organization trail, so the incident is smaller than it appears — but any
downstream tooling keyed to the deleted trail's bucket goes quiet, and that disruption is real even
though the audit record is not affected.
