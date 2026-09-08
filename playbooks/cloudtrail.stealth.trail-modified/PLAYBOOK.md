# IR Playbook: CloudTrail Trail Modified — coverage narrowed via `UpdateTrail` and `PutEventSelectors`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence evasion — a trail is reconfigured so that it keeps logging and reporting healthy while capturing less, delivering elsewhere, or delivering under a key nobody can read |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when global service events or the KMS key change; high otherwise. The source pack rates this P3, below stopping and deleting a trail, although it is the only one of the three that no health check will corroborate. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | CloudTrail, S3, KMS, IAM |

**What the technique does:** the actor changes what a trail captures or where it goes, without
stopping or deleting it. `IsLogging` stays true, `describe-trails` still returns the trail,
`LatestDeliveryTime` keeps moving. Four changes matter, and they are all one API call:

| Change | Effect |
|---|---|
| `isMultiRegionTrail` → false | Every Region but the home Region stops being covered |
| `includeGlobalServiceEvents` → false | IAM, STS and CloudFront become invisible — those events are recorded in `us-east-1` and delivered only to trails that include them |
| `s3BucketName` changed | Still logging, to a bucket nobody queries |
| `kmsKeyId` changed | Logs delivered intact, correctly sized, and undecryptable |

A fifth path does not touch `UpdateTrail` at all: `PutEventSelectors` replaces a trail's selector
list wholesale, so one call removes every data-event and network-activity selector.

**Why the usual reflexes miss it.** The first is to trust the health check — there is no status
field that shows any of this, and every dashboard stays green. The second is to scope the rule to
`UpdateTrail`, which is what the source rule does and which misses the selector call entirely. The
third is to treat all `UpdateTrail` calls alike: one that *enables* log file validation looks
identical to one that turns off global service events. The fourth is to restore selectors from
memory, which reproduces management-events-only coverage and looks correct.

**Detection thesis:** read what changed rather than that something changed, cover the selector call
as a first-class signal, and rate on the specific effect.

**Adjacent playbooks.** The trail paused is `../cloudtrail.stealth.trail-logging-stopped/`; removed,
`../cloudtrail.impact.trail-deleted/`. The downstream symptom of a redirect or key change is
`../cloudtrail.stealth.no-logs-received/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

**A recorded baseline of each trail's configuration and selectors.** This is the load-bearing
prerequisite and it is different from the other CloudTrail playbooks: the incident is a *difference*,
so without a previous state there is nothing to compare against and the alert is unresolvable. A
scheduled `describe-trails` plus `get-event-selectors` export is enough.

An **organization trail** owned by the management account. Member accounts cannot *"change what
types of events are logged, or otherwise alter organization trails in any way"*, so the technique
fails against one.

Knowledge of which trails carry `IncludeGlobalServiceEvents`. IAM and STS activity reaches only
those, so the flag is a single point of failure for every identity detection in the estate.

**Alerting (must be pre-configured)**

- **`UpdateTrail` sets `includeGlobalServiceEvents` false — IAM and STS become invisible while the trail reports healthy → P0**
- **`UpdateTrail` changes `kmsKeyId` — logs keep arriving and become undecryptable → P0**
- **`UpdateTrail` changes `s3BucketName` to a destination not on the recorded list → P0**
- **Three or more CloudTrail configuration changes by one principal within an hour → P0**

**Response Tooling**

An IAM principal that can call `cloudtrail update-trail`, `put-event-selectors`,
`get-event-selectors` and `lookup-events` outside the change pipeline, in the trail's home Region.

Read access to the trail's destination bucket **and** the ability to decrypt an object there. That
combination is what detects a KMS key change, and neither half alone does.

**Known IOC Baselines**

The buckets that legitimately receive trail logs, populating `known_destinations` in the shipped
rules. Deployed empty, the destination rule fires on every trail update that restates its current
bucket — which most IaC applies do.

The roles that legitimately manage CloudTrail, populating `known_provisioners` on the selector rule.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `UpdateTrail` sets `includeGlobalServiceEvents` false — IAM, STS and CloudFront stop reaching the trail | CloudTrail | T1685.002 |
| P0 | `UpdateTrail` changes `kmsKeyId` — logs continue to arrive and become undecryptable without the new key | CloudTrail | T1685.002 |
| P0 | `UpdateTrail` changes `s3BucketName` to a destination not on the recorded list | CloudTrail | T1685.002 |
| P0 | Three or more CloudTrail configuration changes by one principal within an hour | Correlation rule | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `PutEventSelectors` or `PutInsightSelectors` by a principal that is not a recorded provisioner | CloudTrail | T1685.002 |
| P2 | `UpdateTrail` sets `isMultiRegionTrail` or `enableLogFileValidation` false | CloudTrail | T1685.002 |
| P2 | A trail reporting `IsLogging` true whose destination bucket has received no new object in over 3 hours | State check | T1685.002 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Rated P3 — below stopping and deleting a trail in the same pack | This is the only one of the three that no health check corroborates. `IsLogging` stays true, the trail stays listed, delivery timestamps keep moving. Rating the invisible case lowest inverts the order | Critical for global service events and the KMS key, high for the rest |
| Scoped to `UpdateTrail` only | Coverage is narrowed by `PutEventSelectors`, a different call. Selectors are replaced wholesale, so one call removes every data-event and network-activity selector — and this rule never fires | A dedicated rule on `PutEventSelectors` and `PutInsightSelectors` |
| No content check on a highly configurable call | An `UpdateTrail` that *enables* log file validation is reported identically to one that turns global service events off. Four distinct abuses, one output | Four separate conditions, rated by effect, reading only fields that are present |
| Matches `eventSource.keyword` | That suffix is an index-mapping artefact, not part of the CloudTrail record. Sibling rules in the same pack match plain `eventSource`, so the pack writes one field two ways and this rule works against one mapping | Plain field name. Sigma is mapping-agnostic and the backend applies its own conventions |
| No sequence dimension | Any single configuration change has an innocent reading. Three by one identity in an hour does not, and a per-event P3 will never surface it | An `event_count` correlation at three changes per principal per hour |

**Recommended detection — the four abuses, the selector call, and the sequence.**

```yaml
# CloudTrail trail modified (T1685.002)
#
# THE STEALTHIEST OF THE THREE TAMPERING TECHNIQUES, RATED LOWEST BY THE SOURCE PACK. A modified
# trail stays present, keeps logging and reports healthy in every summary view.
#
# It also matches `UpdateTrail` only, which is not how coverage is narrowed — selectors are set by
# PutEventSelectors, replaced wholesale rather than merged. And UpdateTrail has four distinct abuses
# the rule does not separate: multi-Region off, global service events off, bucket redirected, KMS key
# changed. Full rationale: detections/detection_note_t1685_002.md.
title: CloudTrail trail coverage reduced
id: 5a2f81c6-4bd0-4739-91ea-63c07f2b8d94
name: cloudtrail_trail_coverage_reduced
status: experimental
description: >-
  UpdateTrail turned off multi-Region coverage, global service events, or log file validation. The
  trail stays present and keeps reporting as logging, so every check that asks whether logging is
  enabled passes. Turning off global service events is the sharpest of the three: IAM, STS and
  CloudFront events are recorded in us-east-1 and delivered only to trails that include them, so
  this single flag makes identity activity invisible while the trail looks healthy.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html
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
    eventName: 'UpdateTrail'
  success:
    errorCode: null
  multiregion_off:
    requestParameters.isMultiRegionTrail: false
  global_events_off:
    requestParameters.includeGlobalServiceEvents: false
  validation_off:
    requestParameters.enableLogFileValidation: false
  condition: selection and success and (multiregion_off or global_events_off or validation_off)
falsepositives:
  - >-
    A trail being deliberately narrowed for cost, which does happen and should arrive with a change
    record. It is also exactly what this technique looks like, so the change record is the only
    thing that separates them.
level: critical
---
title: CloudTrail trail destination or encryption key changed
id: c93e6b70-18a4-4d52-8f61-2b7d05ea34c9
name: cloudtrail_trail_destination_changed
status: experimental
description: >-
  UpdateTrail changed the destination bucket or the KMS key. Both leave the trail logging and both
  end the flow of readable records into the defender's pipeline — a redirected bucket lands the logs
  somewhere nobody queries, and a changed KMS key delivers them intact and undecryptable to anyone
  without access to the new key. The second is the worse of the two because the objects are present
  and correctly sized, so a volume-based health check sees nothing wrong.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html
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
    eventName: 'UpdateTrail'
  success:
    errorCode: null
  destination_present:
    requestParameters.s3BucketName|exists: true
  key_present:
    requestParameters.kmsKeyId|exists: true
  # POPULATE BEFORE DEPLOYING with the buckets that legitimately receive trail logs. Deployed empty
  # this fires on every trail update that restates the current destination, which most do.
  known_destinations:
    requestParameters.s3BucketName:
      - 'org-cloudtrail-logs'
      - 'org-cloudtrail-logs-archive'
  condition: selection and success and (destination_present or key_present) and not known_destinations
falsepositives:
  - >-
    A trail update that restates the existing bucket unchanged, which the API accepts and which IaC
    tools do routinely. Populating known_destinations removes these; widening the rule does not.
level: high
---
title: CloudTrail event selectors changed
id: 71d0af38-9c62-4e15-b804-5ea36c9f1207
name: cloudtrail_event_selectors_changed
status: experimental
description: >-
  PutEventSelectors or PutInsightSelectors was called. This is how what a trail captures is actually
  narrowed, and it is a different call from UpdateTrail — a rule scoped to UpdateTrail never sees
  it. Because selectors are replaced wholesale rather than merged, a single call can remove every
  data-event and network-activity selector while the trail continues to report as logging.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html
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
    eventName:
      - 'PutEventSelectors'
      - 'PutInsightSelectors'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    An infrastructure apply that restates the selectors on every run. Allowlist the role; the
    comparison against the previous selector set, which the playbook does, is what distinguishes a
    restatement from a reduction.
level: high
---
title: CloudTrail configuration changed repeatedly by one principal
id: 8b47c05e-2d91-4a68-b3f7-e015d2a7648b
status: experimental
description: >-
  One principal made three or more CloudTrail configuration changes within an hour. Any single
  change has an innocent reading; a sequence of them by one identity in one hour is someone working
  through the configuration, and it is the shape that a per-event rule at P3 will never surface.
references:
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
correlation:
  type: event_count
  rules:
    - cloudtrail_config_changed
  group-by:
    - userIdentity.arn
  timespan: 1h
  condition:
    gte: 3
falsepositives:
  - >-
    A deployment that creates and configures several trails in one run. Allowlist the pipeline role
    on the base rule rather than raising the threshold, which would only make the attacker case
    harder to reach as well.
level: critical
---
title: CloudTrail configuration changed
id: e6014c9d-53b8-42f7-a09e-c8b715f3a2d6
name: cloudtrail_config_changed
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful call that
  changes a trail's configuration or its selectors.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName:
      - 'UpdateTrail'
      - 'PutEventSelectors'
      - 'PutInsightSelectors'
      - 'StopLogging'
      - 'DeleteTrail'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: it cannot tell you what the configuration was *before* the
change. Every finding here is a difference, and the previous state lives in the trail's own event
history or in the §1 baseline export — nowhere else.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first; it establishes what actually changed, which is the whole incident.

#### Query 1 — Reconstruct: what changed, and what it was before

```bash
TRAIL="${1:?trail name from the alert required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-90d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in UpdateTrail CreateTrail PutEventSelectors PutInsightSelectors; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg t "$TRAIL" '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | select((.requestParameters.name // .requestParameters.trailName) == $t)
      | .requestParameters as $r
      # Absent is NOT false. UpdateTrail accepts a partial document, so a flag that is not present
      # was not changed — printing "-" keeps the two apart.
      | def f(k): if ($r[k] == null) then "-" else ($r[k] | tostring) end;
        "\(.eventTime)  \(.eventName)  \(.userIdentity.arn)",
        "    multiRegion=\(f("isMultiRegionTrail"))  globalEvents=\(f("includeGlobalServiceEvents"))  validation=\(f("enableLogFileValidation"))",
        "    bucket=\(f("s3BucketName"))  kms=\(f("kmsKeyId"))",
        "    selectors=\((.requestParameters.eventSelectors // .requestParameters.advancedEventSelectors // "-") | tostring | .[0:200])"'
done | sort
```

Read this as consecutive states, not as events. The line before the alerted change is what the
configuration was, and the difference between the two lines is the entire finding. A `-` means that
field was not in the request and therefore did not change — treating it as `false` invents findings
that will not survive review.

#### Query 2 — Compare the live configuration against the baseline

```bash
TRAIL="${1:?trail name required}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== Live trail configuration ==="
aws cloudtrail describe-trails --trail-name-list "$TRAIL" --region "$REGION" --output json 2>/dev/null \
| jq -r '.trailList[]
    | "  multiRegion=\(.IsMultiRegionTrail)  globalEvents=\(.IncludeGlobalServiceEvents)",
      "  validation=\(.LogFileValidationEnabled)  org=\(.IsOrganizationTrail)",
      "  bucket=\(.S3BucketName)  kms=\(.KmsKeyId // "none")  home=\(.HomeRegion)"'

echo
echo "=== Live selectors — this is what the trail actually captures ==="
aws cloudtrail get-event-selectors --trail-name "$TRAIL" --region "$REGION" --output json 2>/dev/null \
| jq -r 'if (.AdvancedEventSelectors // empty) then
           .AdvancedEventSelectors[] | "  advanced: \(.Name // "unnamed")"
         elif (.EventSelectors // empty) then
           .EventSelectors[] | "  basic: readWrite=\(.ReadWriteType) mgmt=\(.IncludeManagementEvents) dataResources=\([.DataResources[]?.Type] | join(","))"
         else "  [!] NO SELECTORS — this trail captures nothing beyond the default" end'

echo
echo "=== Is it still reporting healthy? (it will be) ==="
aws cloudtrail get-trail-status --name "$TRAIL" --region "$REGION" \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}' \
  --output json 2>/dev/null
```

The third block is included precisely because it will look fine. `IsLogging: true` with a recent
`LatestDeliveryTime` is the expected output of a successfully modified trail, and seeing it stated
next to the reduced selectors is what stops it being read as reassurance.

#### Query 3 — Confirm the destination is still readable

```bash
TRAIL="${1:?trail name required}"
REGION="${AWS_REGION:-us-east-1}"
BUCKET="$(aws cloudtrail describe-trails --trail-name-list "$TRAIL" --region "$REGION" \
           --query 'trailList[0].S3BucketName' --output text 2>/dev/null)"
KEY="$(aws cloudtrail describe-trails --trail-name-list "$TRAIL" --region "$REGION" \
        --query 'trailList[0].KmsKeyId' --output text 2>/dev/null)"

echo "Destination: ${BUCKET:-unknown}   KMS: ${KEY:-none}"

LATEST="$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix AWSLogs/ --max-items 1 \
           --query 'Contents[0].Key' --output text 2>/dev/null)"
if [ -z "$LATEST" ] || [ "$LATEST" = "None" ]; then
  echo "[FAIL] cannot list ${BUCKET} — the destination may have been redirected somewhere you cannot read"
  exit 1
fi

# A KMS key change leaves objects arriving, correctly sized and on schedule. Only an attempt to
# READ one fails, which is why this downloads rather than checking metadata.
if aws s3 cp "s3://${BUCKET}/${LATEST}" /dev/null >/dev/null 2>&1; then
  echo "[OK] a recent log object is readable — the destination and key are still usable"
else
  echo "[FAIL] the object exists but cannot be read. If kmsKeyId changed, logs are being delivered"
  echo "       intact and undecryptable, and every volume or freshness check will look healthy."
fi
```

This is the only check that catches a KMS key change. Object counts, sizes and timestamps all stay
normal — the failure surfaces only on a read, and usually during the next incident rather than this
one.

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

What comes **after** the change matters most here. Unlike a stop, this leaves the trail running, so
the actor's subsequent activity is still recorded — unless it fell inside exactly the coverage they
removed, which is the point of comparing the new selectors against the old.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore coverage first — it is a single call and it is the only thing that stops the loss
accumulating. The comparison work in Query 1 can continue afterwards.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 3 shows the
destination is unreadable, treat this as an active blackout even though every status field is green:
logs are being written to somewhere you cannot get them, and the longer that stands the more of the
incident is unrecoverable.

#### Step 1 — Restore full coverage

```bash
TRAIL="${1:?trail name required}"
REGION="${2:-${AWS_REGION:-us-east-1}}"
BUCKET="${3:?the correct destination bucket from the baseline}"

# All flags are sent explicitly. UpdateTrail accepts a partial document, so restoring one setting by
# name leaves the others exactly as the actor left them.
aws cloudtrail update-trail --name "$TRAIL" --region "$REGION" \
  --s3-bucket-name "$BUCKET" \
  --is-multi-region-trail \
  --include-global-service-events \
  --enable-log-file-validation \
  && echo "[OK] coverage restored on $TRAIL"

aws cloudtrail describe-trails --trail-name-list "$TRAIL" --region "$REGION" --output json 2>/dev/null \
| jq -r '.trailList[] | "multiRegion=\(.IsMultiRegionTrail) globalEvents=\(.IncludeGlobalServiceEvents) validation=\(.LogFileValidationEnabled) bucket=\(.S3BucketName)"'
```

Note that this does **not** restore the KMS key. If `kmsKeyId` was changed, decide deliberately
whether to return to the previous key or move to a new one — returning to a key the actor may have
had access to is not obviously right, and the choice belongs to a human.

#### Step 2 — Restore the selectors, from the history and not from memory

```bash
TRAIL="${1:?trail name required}"
REGION="${2:-${AWS_REGION:-us-east-1}}"
START="$(date -u -v-90d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%SZ')"
OUT="./recovered-${TRAIL}-selectors.json"

# Selectors are REPLACED, not merged, so the previous set exists only in the previous
# PutEventSelectors event. Restoring from memory reproduces management-events-only coverage and
# looks correct.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutEventSelectors \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg t "$TRAIL" '[.Events[].CloudTrailEvent | fromjson
    | select(.errorCode == null)
    | select((.requestParameters.trailName // .requestParameters.name) == $t)]
    | sort_by(.eventTime)
    | if length < 2 then empty else .[-2].requestParameters end' > "$OUT"

if [ -s "$OUT" ]; then
  echo "[OK] previous selector set recovered -> $OUT"
  jq -r '.' "$OUT"
  echo "[!] Review before applying — the previous set is not automatically the correct one."
else
  echo "[FAIL] no earlier PutEventSelectors for $TRAIL. Rebuild from the §1 baseline export."
  echo "       Do NOT assume the default: management events only is what the actor wanted."
fi
```

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

#### Step 4 — Establish what fell in the gap

The gap here is not a period of no logging — it is a *shape*. Work out precisely which events
stopped being captured and for how long, because that is what the rest of the investigation has to
treat as unknown:

- `includeGlobalServiceEvents` off → **IAM, STS and CloudFront** for the whole period.
- `isMultiRegionTrail` off → **every Region except the home Region**.
- Selectors narrowed → whichever data-event or network-activity resources were removed.
- Bucket redirected or KMS key changed → **everything**, but recoverable if the new destination can
  be reached.

Only the last of those may be retrievable. The others were never written.

---

## 4. Eradication

### Remove Attacker Access

#### Reconstruct the shaped gap from independent sources

Because the trail kept running, most activity is still recorded — the loss is specific. Where global
service events were off, IAM and STS activity for the period is missing and AWS Config's
configuration items are the best substitute, since IAM changes appear there as state. Where a Region
was dropped, that Region's service-specific logs (VPC flow logs, ALB, S3 access logs) still exist.

#### Recover the logs if the destination was merely redirected

A redirected bucket is the recoverable case: the objects were written, just somewhere else. If the
new destination is in an account you control, collect them and treat the gap as closed. If it is
not, the gap is real and the redirect is also an exfiltration finding — the trail was writing your
audit log into someone else's bucket.

#### Deny the operations outside a break-glass path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyCloudTrailReconfiguration",
  "Effect": "Deny",
  "Action": ["cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors",
             "cloudtrail:PutInsightSelectors", "cloudtrail:StopLogging", "cloudtrail:DeleteTrail"],
  "Resource": "*",
  "Condition": {"ArnNotLike": {"aws:PrincipalARN": "arn:aws:iam::*:role/YourBreakGlassRole"}}
}
```

Attach it to an OU, not the management account, where SCPs do not apply. `YourBreakGlassRole` must
be a role that genuinely exists — an `ArnNotLike` against a non-existent role denies the action to
everyone including you. Test in a non-production OU first.

#### Start exporting the baseline

The reason this incident is hard is that the configuration had no recorded previous state. A
scheduled `describe-trails` and `get-event-selectors` export turns every future occurrence into a
one-line diff, and it is the single change that most reduces the cost of this class of alert.

---

## 5. Recovery

### Restore Clean State

#### Verify the configuration matches the baseline, field by field

```bash
TRAIL="${1:?trail name required}"
REGION="${2:-${AWS_REGION:-us-east-1}}"
BASELINE="${3:?path to the baseline describe-trails export}"

aws cloudtrail describe-trails --trail-name-list "$TRAIL" --region "$REGION" --output json 2>/dev/null \
| jq -r --slurpfile base "$BASELINE" '.trailList[0] as $now
  | ($base[0].trailList[] | select(.Name == $now.Name)) as $was
  | ["IsMultiRegionTrail","IncludeGlobalServiceEvents","LogFileValidationEnabled","S3BucketName","KmsKeyId"][]
  | . as $k
  | if ($now[$k] // "none") == ($was[$k] // "none")
    then "[OK] \($k) = \($now[$k] // "none")"
    else "[FAIL] \($k): was \($was[$k] // "none"), now \($now[$k] // "none")" end'
```

#### Verify the selectors, which are the part most likely to be wrong

```bash
TRAIL="${1:?trail name required}"
REGION="${2:-${AWS_REGION:-us-east-1}}"

aws cloudtrail get-event-selectors --trail-name "$TRAIL" --region "$REGION" --output json 2>/dev/null \
| jq -r 'if (.AdvancedEventSelectors // []) | length > 0 then
           "[OK] \((.AdvancedEventSelectors | length)) advanced selector(s) configured"
         elif (.EventSelectors // []) | length > 0 then
           (.EventSelectors[] | "[ ] basic selector: readWrite=\(.ReadWriteType) mgmt=\(.IncludeManagementEvents) data=\([.DataResources[]?.Type] | join(",") // "none")")
         else "[FAIL] no selectors — the trail captures only default management events" end'
```

A trail with no data-event selectors is the state a narrowing attack leaves behind, and it is also
the AWS default — so this check cannot distinguish "never configured" from "reduced". Only the
baseline can, which is why §4 makes the export the substantive recommendation.

#### Verify the logs are readable end to end

```bash
TRAIL="${1:?trail name required}"
REGION="${2:-${AWS_REGION:-us-east-1}}"

# Re-run §2 Query 3: a readable object is the only proof that the destination and key are usable.
BUCKET="$(aws cloudtrail describe-trails --trail-name-list "$TRAIL" --region "$REGION" \
           --query 'trailList[0].S3BucketName' --output text 2>/dev/null)"
LATEST="$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix AWSLogs/ --max-items 1 \
           --query 'Contents[0].Key' --output text 2>/dev/null)"
if [ -n "$LATEST" ] && [ "$LATEST" != "None" ] && aws s3 cp "s3://${BUCKET}/${LATEST}" /dev/null >/dev/null 2>&1; then
  echo "[OK] logs are being delivered to $BUCKET and are readable"
else
  echo "[FAIL] logs are not readable — recovery is not complete regardless of what IsLogging says"
fi
```

#### Confirm the corrected detection fires

```bash
TRAIL="${1:?a NON-PRODUCTION trail name required}"
REGION="${2:-${AWS_REGION:-us-east-1}}"

# Exercise log file validation, which is the least harmful of the four flags: turning it off reduces
# no coverage at all, so nothing is lost during the test, and it still exercises the
# coverage-reduced rule.
aws cloudtrail update-trail --name "$TRAIL" --region "$REGION" --no-enable-log-file-validation \
  && echo "[OK] validation disabled — expect the coverage-reduced rule within 15 min"

sleep 60
aws cloudtrail update-trail --name "$TRAIL" --region "$REGION" --enable-log-file-validation \
  && echo "[OK] restored"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Which of the four settings changed, and what was it before? | The incident is a difference. Without the previous state there is no finding, only an event. |
| Was there a baseline export to compare against? | If not, that is the finding, because it is why the alert took hours to resolve. |
| Did the selectors change, and were they restored from history or from memory? | Selectors are replaced wholesale and default to management events only, so a restoration from memory silently reproduces the reduction. |
| Was the destination or KMS key changed, and were the logs still readable? | Only a read attempt shows this. Every volume, freshness and status check stays green. |
| How long did the reduced configuration stand? | It sizes the shaped gap — which events were not captured, rather than a period of no events. |
| Did any health dashboard show a problem at any point? | It should not have, and confirming that is what justifies keeping this detection rather than relying on monitoring. |

### Recommended Guardrails

**Export trail configuration and selectors on a schedule.** Every finding here is a difference, so
the baseline is not a nice-to-have — it is the thing that makes the alert resolvable at all.

**Alert on the effect, not the call.** An `UpdateTrail` that enables validation and one that turns
off global service events are the same event name. A rule that does not read the request body cannot
tell a hardening from an attack.

**Cover `PutEventSelectors` explicitly.** It is a different call from `UpdateTrail`, it is how
coverage is actually narrowed, and selectors are replaced rather than merged so one call is enough.

**Rate this above stopping a trail, not below it.** It is the only tampering technique that leaves
every status field green, which makes it the one where a detection is doing work that monitoring
cannot.

**Monitor the destination for readability, not just for objects.** A KMS key change delivers logs
that are present, correctly sized, on schedule and useless. Periodically reading one object is the
only check that catches it.

### Technique Reference

**T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log.** Verified live at
https://attack.mitre.org/techniques/T1685/002/ on 2026-08-30.

AWS references relied on throughout, all verified 2026-08-30:

- `UpdateTrail` API reference — the configurable fields and their semantics:
  https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html
- `PutEventSelectors` API reference — selectors replaced rather than merged:
  https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html
- CloudTrail concepts — the four event types, the management-only default, and global service event
  delivery: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html

Service-wide verified behaviour shared by every `cloudtrail.*` playbook is in
`../_ground-truth/cloudtrail.md`.

### Residual Risk

**Without a baseline, a reduction is indistinguishable from a default.** A trail with no data-event
selectors is both what an attack leaves behind and what AWS creates by default. No API call
separates them; only a recorded previous state does.

**The `known_destinations` list decides whether the redirect rule works at all.** Deployed empty it
fires on every trail update that restates the current bucket, which most IaC applies do, and it will
be tuned off within a week. Deployed populated it is one of the highest-value rules here.

**A KMS key change is only detectable by reading.** Nothing in `get-trail-status`,
`describe-trails`, object counts, object sizes or delivery timestamps changes. If the periodic read
check in §5 is not running, this can stand indefinitely and will be discovered during the next
incident, when the logs are needed and cannot be opened.

**Network activity events and Insights selectors are covered only as event names.** The rules fire
on `PutInsightSelectors` but do not evaluate what the new selector set contains, so a narrowing
within those types is reported as a change rather than as a reduction. Resolving it needs the same
baseline comparison as everything else here.
