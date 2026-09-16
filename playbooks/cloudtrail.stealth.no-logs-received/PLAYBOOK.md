# IR Playbook: CloudTrail Delivery Silently Failing — no logs arriving while `IsLogging` stays true

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence evasion — CloudTrail records stop reaching their destination because the delivery path was broken outside CloudTrail, while the trail continues to report as logging |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when the destination bucket or its KMS key is removed; high for a policy or lifecycle change. The silence itself is a symptom and is rated below its causes, which reverses the source pack's ordering. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | CloudTrail, S3, KMS, IAM |

**What the technique does:** the actor breaks the delivery path rather than the trail. The trail is
untouched — `IsLogging` true, present in `describe-trails`, selectors intact — and the records stop
arriving anyway, because:

| Change | Effect |
|---|---|
| Destination bucket policy drops the `cloudtrail.amazonaws.com` write statement | Delivery fails; only `LatestDeliveryError` shows it |
| Destination bucket deleted | Delivery fails **and the historical log files are gone with it** |
| Lifecycle rule with a short expiry | Logs arrive, then are deleted — evidence destruction on a timer |
| KMS key disabled or scheduled for deletion | Delivery fails, or objects arrive permanently unreadable |

The bucket deletion is the only action anywhere in this playbook set that destroys the **historical**
record. AWS is explicit that deleting a *trail* leaves the bucket and its files intact, so the trail
is not where the evidence is at risk — the bucket is.

**Why the usual reflexes miss it.** The first is to write an absence rule in a rule engine: nothing
evaluates when nothing arrives, so it reports clean forever and clean-forever looks like working.
The second is to alert on the silence and rate it above the causes, which is what the source pack
does — the causes arrive first and name what happened. The third is to group the heartbeat by the
ingestion stream, which cannot distinguish a stopped trail from a broken collector, an expired
credential or a dormant account. The fourth is to look at CloudTrail for the answer when the fault
is in S3 or KMS.

**Detection thesis:** put the heartbeat in a scheduled check where absence can actually be observed,
and alert on the delivery-path changes as ordinary events, because they are.

**Adjacent playbooks.** The trail stopped is `../cloudtrail.stealth.trail-logging-stopped/`;
deleted, `../cloudtrail.impact.trail-deleted/`; reconfigured,
`../cloudtrail.stealth.trail-modified/`. Those cover the causes inside CloudTrail; this one covers
the causes outside it.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

**A scheduled delivery check — this is the heartbeat, and it cannot be a rule.** An event-driven
engine evaluates when an event arrives; when none arrives, nothing evaluates. The check must run on
a schedule, read state, and alarm on it:

```bash
# Run every 15 minutes, per trail, in the trail's home Region.
aws cloudtrail get-trail-status --name "$TRAIL" --region "$HOME_REGION" --output json \
| jq -r --arg t "$TRAIL" '
    if .IsLogging != true then "[ALARM] \($t): IsLogging is false"
    elif ((.LatestDeliveryError // "") != "") then "[ALARM] \($t): delivery failing — \(.LatestDeliveryError)"
    elif ((now - ((.LatestDeliveryTime // 0) | tonumber)) > 10800) then "[ALARM] \($t): no delivery in 3h"
    else "[OK] \($t)" end'
```

`LatestDeliveryError` is the field that shows a bucket-policy or KMS failure and **nothing emits it
as an event**. A rule set alone cannot see this class of incident at all.

The bucket and KMS key identity for every trail, recorded. The shipped rules match on those, and
deployed with placeholder values they are a general S3 and KMS monitor rather than a CloudTrail one.

Versioning and Object Lock on the destination bucket, so that a lifecycle rule or a delete cannot
remove log objects that have already arrived.

**Alerting (must be pre-configured)**

- **A trail's destination bucket is deleted → P0**
- **A KMS key used by a trail is disabled or scheduled for deletion → P0**
- **Two or more delivery-path changes by one principal within an hour, across the trail and its destination → P0**

**Response Tooling**

An IAM principal that can call `s3api put-bucket-policy`, `kms enable-key`,
`kms cancel-key-deletion` and `cloudtrail get-trail-status` outside the change pipeline.

The ability to **read** an object from each trail's destination bucket. That is the only check that
detects a KMS key problem — object counts, sizes and timestamps all stay normal.

**Known IOC Baselines**

The correct bucket policy for each trail destination, kept outside the bucket. Restoring it is the
containment action, and reconstructing it during an incident is slow.

The list of principals allowed to change the log bucket or its key. In most estates this should be
narrower than the list allowed to change CloudTrail itself, because the log bucket is where the
evidence actually lives.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `DeleteBucket` on a trail's destination bucket — delivery fails and the historical logs go with it | CloudTrail (S3) | T1685.002 |
| P0 | `DisableKey` or `ScheduleKeyDeletion` on a KMS key a trail encrypts with | CloudTrail (KMS) | T1685.002 |
| P0 | Two or more delivery-path changes by one principal within an hour, across the trail and its destination | Correlation | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `PutBucketPolicy` or `DeleteBucketPolicy` on a trail destination bucket | CloudTrail (S3) | T1685.002 |
| P2 | `PutLifecycleConfiguration` on a trail destination bucket — a short expiry deletes logs after they arrive | CloudTrail (S3) | T1685.002 |
| P2 | The scheduled check reports `LatestDeliveryError` non-empty while `IsLogging` is true | State check | T1685.002 |

### Detection Rule Quality Notes

The source rule is a threshold rule and is fully readable, so every row below is auditable against
`_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| It is an absence rule inside an event-driven engine | Nothing evaluates when nothing arrives, so it reports clean forever — which is indistinguishable from working. The one failure mode a detection must not have is looking healthy when it is inert | The heartbeat is specified as a **scheduled state check** in §1 and is deliberately not shipped as a rule |
| Rated P1, above every cause in the same pack | Stopping a trail is P2, deleting it P2, modifying it P3. The causes arrive first and name what happened; the silence arrives up to two hours later and says only that something is wrong | The causes are rated critical and high here; the symptom is a P2 confirmation |
| `group_by` is the ingestion pipeline's stream identifier | It detects "this stream went quiet", conflating a stopped trail with a broken collector, an expired credential, a network fault and a dormant account. The benign causes are more common, which is how a P1 becomes an ignored P1 | Group by trail, and pair the alarm with `get-trail-status` so "did AWS stop delivering, or did we stop receiving?" is answered before a human is paged |
| No coverage of the causes outside CloudTrail | Delivery fails with `IsLogging` still true when the bucket policy, the bucket, its lifecycle, or the KMS key changes. Each is an ordinary S3 or KMS event and no CloudTrail-scoped rule set sees any of them | Three rules on those events, matched against the recorded bucket and key identity |
| 2-hour window with a threshold of 1 | Sets the floor at two hours of undetected silence in every case, including the ones where an event was available immediately | The event rules fire at once; the scheduled check is the backstop rather than the primary signal |

**Recommended detection — the delivery-path causes, plus the heartbeat's base stream.**

```yaml
# CloudTrail delivery silently failing (T1685.002)
#
# ABSENCE CANNOT BE DETECTED BY AN EVENT-DRIVEN ENGINE — nothing evaluates when nothing arrives, so
# an absence rule reports clean forever. The heartbeat is a SCHEDULED check, specified in
# ../PLAYBOOK.md §1, not a rule.
#
# What CAN be detected are the silent causes no CloudTrail-scoped rule covers: the destination
# bucket's policy, its deletion, a lifecycle expiry, and the KMS key being disabled or scheduled for
# deletion. Each leaves IsLogging true.
# Full rationale: detections/detection_note_t1685_002.md.
title: KMS key used by a CloudTrail trail disabled or scheduled for deletion
id: 0a7d3e51-96c8-4b24-a70f-51c8e4b0d937
name: cloudtrail_destination_key_disabled
status: experimental
description: >-
  A KMS key was disabled or scheduled for deletion. Where that key encrypts a trail's log files,
  delivery fails or the delivered objects become unreadable while the trail continues to report
  IsLogging true — which is the silence the "no logs" rule notices hours later, arriving here as an
  actionable event instead. Populate the key list with the keys your trails actually use; without
  that this fires on ordinary key lifecycle.
references:
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
    eventSource: 'kms.amazonaws.com'
    eventName:
      - 'DisableKey'
      - 'ScheduleKeyDeletion'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the KMS key IDs or aliases your trails encrypt with. Deployed
  # empty this alerts on every key disabled anywhere in the account.
  trail_keys:
    requestParameters.keyId|contains:
      - 'alias/cloudtrail'
      - 'alias/audit-logs'
  condition: selection and success and trail_keys
falsepositives:
  - >-
    A planned key rotation that disables the old key after the trail has been moved to a new one.
    The UpdateTrail changing kmsKeyId should appear first; its absence is what makes this a finding.
level: critical
---
title: CloudTrail destination bucket policy or lifecycle changed
id: b41f7092-e6a3-4d18-95c7-2a80d6f4e31b
name: cloudtrail_destination_bucket_altered
status: experimental
description: >-
  The policy or lifecycle configuration of a bucket that receives trail logs was changed. Removing
  the statement that allows cloudtrail.amazonaws.com to write makes delivery fail, and a lifecycle
  rule with a short expiry deletes the logs after they arrive. In both cases the trail keeps
  reporting as logging and LatestDeliveryError is the only field that moves — and it is not an
  event, so nothing alerts on it.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'PutBucketPolicy'
      - 'DeleteBucketPolicy'
      - 'PutLifecycleConfiguration'
      - 'PutBucketVersioning'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the buckets your trails deliver to.
  trail_buckets:
    requestParameters.bucketName|contains:
      - 'cloudtrail'
      - 'audit-logs'
  condition: selection and success and trail_buckets
falsepositives:
  - >-
    Routine lifecycle management on the log archive. It should be rare on this bucket specifically,
    and a shortened expiry is worth reading every time — it is indistinguishable from evidence
    destruction on a delay.
level: high
---
title: CloudTrail destination bucket deleted
id: 6c5b28ea-70d4-41f9-83b6-e9027a4c1d58
name: cloudtrail_destination_bucket_deleted
status: experimental
description: >-
  A bucket that receives trail logs was deleted. Delivery fails from that moment and the historical
  log files are gone with it — which is the one way the past record is actually destroyed, since
  deleting the trail itself explicitly leaves the bucket and its contents intact.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'DeleteBucket'
  success:
    errorCode: null
  trail_buckets:
    requestParameters.bucketName|contains:
      - 'cloudtrail'
      - 'audit-logs'
  condition: selection and success and trail_buckets
falsepositives:
  - >-
    Decommissioning an archive bucket that no trail still points at. Confirm against describe-trails
    before closing, because a trail pointing at a deleted bucket keeps reporting as logging.
level: critical
---
title: Any CloudTrail management event
id: 3d80c17f-4a52-4e69-b1c3-750f9e2b8a46
name: cloudtrail_any_management_event
status: experimental
description: >-
  Base rule — NOT a detection and not routable. It exists to define the heartbeat signal that the
  scheduled delivery check in ../PLAYBOOK.md §1 monitors. Absence cannot be detected by an
  event-driven engine, because nothing evaluates when nothing arrives; the check has to be a
  scheduled alarm on this stream's freshness, and this rule names the stream.
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  # justified: this is deliberately unrestricted. The rule's purpose is to define "a CloudTrail
  # event arrived at all" for a freshness alarm, so any narrowing would defeat it. It is shipped at
  # informational and must never be routed to a human.
  selection:
    eventVersion|exists: true
  condition: selection
level: informational
```

What this set structurally cannot do: it cannot observe the silence itself. That belongs to the
scheduled check in §1, and no rule in any engine substitutes for it.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first. It answers the only question that matters at the start: did AWS stop delivering,
or did we stop receiving?

#### Query 1 — Triage: is AWS still delivering

```bash
REGION="${AWS_REGION:-us-east-1}"

for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --region "$R" --query 'trailList[].[Name,S3BucketName,KmsKeyId]' \
    --output text 2>/dev/null | while IFS=$'\t' read -r NAME BUCKET KEY; do
      [ -z "$NAME" ] && continue
      aws cloudtrail get-trail-status --name "$NAME" --region "$R" --output json 2>/dev/null \
      | jq -r --arg n "$NAME" --arg r "$R" --arg b "$BUCKET" --arg k "$KEY" '
          # LatestDeliveryError is the ONLY field that shows a bucket-policy or KMS failure, and
          # nothing emits it as an event. This is why the heartbeat must read state.
          if .IsLogging != true then
            "[AWS-SIDE] \($r)/\($n): IsLogging FALSE — the trail was stopped"
          elif ((.LatestDeliveryError // "") != "") then
            "[AWS-SIDE] \($r)/\($n): delivery FAILING — \(.LatestDeliveryError)  bucket=\($b) kms=\($k)"
          else
            "[DELIVERING] \($r)/\($n): last delivery \(.LatestDeliveryTime // "unknown")  bucket=\($b)"
          end'
    done
done | sort -u
```

An `[AWS-SIDE]` row means the fault is in AWS and the rest of this playbook applies. If every row
says `[DELIVERING]` and logs are still not arriving in the SIEM, the fault is in the ingestion path
— a collector credential, a network route, a parsing failure — and this is not a security incident
at all. That distinction is what the source rule's stream-level grouping cannot make, and it decides
which team is woken.

#### Query 2 — Reconstruct: what changed on the delivery path

```bash
REGION="${AWS_REGION:-us-east-1}"
BUCKET="${1:?trail destination bucket from Query 1 required}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in PutBucketPolicy DeleteBucketPolicy DeleteBucket PutLifecycleConfiguration \
           PutBucketVersioning DisableKey ScheduleKeyDeletion PutKeyPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg b "$BUCKET" '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | select((.requestParameters.bucketName // "") == $b
               or ((.requestParameters.keyId // "") | test("cloudtrail|audit"; "i")))
      | "\(.eventTime)  \(.eventName)  \(.userIdentity.arn)  " +
        "target=\(.requestParameters.bucketName // .requestParameters.keyId // "-")  ip=\(.sourceIPAddress)"'
done | sort
```

These are the events that produce the silence while leaving the trail reporting healthy. If Query 1
said `[AWS-SIDE]` and this returns nothing, the cause is in CloudTrail itself — go to
`../cloudtrail.stealth.trail-logging-stopped/` or `../cloudtrail.stealth.trail-modified/`.

#### Query 3 — Confirm the destination is writable and readable

```bash
BUCKET="${1:?trail destination bucket required}"

echo "=== Does the policy still let CloudTrail write? ==="
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null \
| jq -r '(if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
    | select(.Effect == "Allow")
    | select((.Principal.Service // "") | tostring | test("cloudtrail"))
    | "[OK] CloudTrail write statement present — Sid=\(.Sid // "-") Action=\(.Action)"' \
  || echo "[FAIL] no bucket policy, or no statement allowing cloudtrail.amazonaws.com to write"

echo
echo "=== Is a recent object readable? (the only check that catches a KMS problem) ==="
LATEST="$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix AWSLogs/ --max-items 1 \
           --query 'Contents[0].Key' --output text 2>/dev/null)"
if [ -z "$LATEST" ] || [ "$LATEST" = "None" ]; then
  echo "[FAIL] no objects under AWSLogs/ — delivery is not landing here at all"
elif aws s3 cp "s3://${BUCKET}/${LATEST}" /dev/null >/dev/null 2>&1; then
  echo "[OK] $LATEST is readable"
else
  echo "[FAIL] $LATEST exists but cannot be read — the KMS key is disabled, deleted, or its policy changed"
fi

echo
echo "=== Is a lifecycle rule deleting the logs after they arrive? ==="
aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" --output json 2>/dev/null \
| jq -r '.Rules[] | select(.Status == "Enabled")
    | "[!] rule \(.ID // "-"): expiration=\(.Expiration.Days // "none") days, prefix=\(.Filter.Prefix // "all")"' \
  || echo "[OK] no lifecycle configuration"
```

The read test is the only one of the three that catches a KMS key change. Object counts, sizes and
timestamps stay entirely normal — the failure surfaces on a read and nowhere else.

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

If delivery genuinely stopped, this output ends at that timestamp for anything the affected trail
was the only source of. Read it together with Query 1's list of trails still `[DELIVERING]`, which
says how much of the picture survives.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore delivery first — until it is restored the gap keeps growing, and unlike a stopped trail
there may be nothing obviously broken to draw attention to it.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 shows
`ScheduleKeyDeletion` on a trail's key, there is a hard deadline: when the waiting period expires
every object encrypted with that key becomes permanently unreadable, and nothing warns again at that
moment. Cancel the deletion before doing anything else.

#### Step 1 — Cancel any pending key deletion, and re-enable the key

```bash
KEY="${1:?KMS key id or alias from Query 2 required}"

STATE="$(aws kms describe-key --key-id "$KEY" --query 'KeyMetadata.KeyState' --output text 2>/dev/null)"
echo "Key state: ${STATE:-unknown}"

case "$STATE" in
  PendingDeletion)
    # The waiting period is 7-30 days and its expiry is silent. Cancelling is reversible; letting it
    # expire is not.
    aws kms cancel-key-deletion --key-id "$KEY" \
      && aws kms enable-key --key-id "$KEY" \
      && echo "[OK] deletion cancelled and key re-enabled"
    ;;
  Disabled)
    aws kms enable-key --key-id "$KEY" && echo "[OK] key re-enabled"
    ;;
  Enabled)
    echo "[OK] key is enabled — if objects are still unreadable, check the key POLICY rather than its state"
    ;;
  *)
    echo "[FAIL] unexpected or missing key state: ${STATE:-none}"
    ;;
esac
```

#### Step 2 — Restore the destination bucket's policy

```bash
BUCKET="${1:?trail destination bucket required}"
BASELINE="${2:?path to the recorded correct bucket policy}"
TS="$(date -u '+%Y%m%dT%H%M%SZ')"

aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text \
  > "/tmp/${BUCKET}-policy-${TS}.json" 2>/dev/null \
  && echo "[OK] current policy preserved at /tmp/${BUCKET}-policy-${TS}.json" \
  || echo "(no current policy — that is itself the fault)"

if [ -s "$BASELINE" ]; then
  aws s3api put-bucket-policy --bucket "$BUCKET" --policy "file://${BASELINE}" \
    && echo "[OK] baseline policy restored on $BUCKET"
else
  echo "[FAIL] no baseline policy at $BASELINE."
  echo "       The trail needs a statement allowing cloudtrail.amazonaws.com to s3:PutObject with"
  echo "       s3:x-amz-acl bucket-owner-full-control, and s3:GetBucketAcl on the bucket itself."
fi

aws cloudtrail get-trail-status --name "${3:-$BUCKET}" --region "${AWS_REGION:-us-east-1}" \
  --query 'LatestDeliveryError' --output text 2>/dev/null
```

`LatestDeliveryError` does not clear instantly — it reflects the last attempt, so re-check it after
the next delivery cycle rather than treating a stale value as failure.

#### Step 3 — Neutralise a lifecycle rule that is deleting logs

```bash
BUCKET="${1:?trail destination bucket required}"

aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" --output json 2>/dev/null \
  > "/tmp/${BUCKET}-lifecycle.json" \
  && echo "[OK] lifecycle preserved at /tmp/${BUCKET}-lifecycle.json"

if [ -s "/tmp/${BUCKET}-lifecycle.json" ]; then
  jq -r '.Rules[] | select(.Status == "Enabled")
         | "[!] \(.ID // "-"): expires after \(.Expiration.Days // "n/a") days"' \
    "/tmp/${BUCKET}-lifecycle.json"
  echo
  echo "[!] Removing a lifecycle rule does NOT restore objects it already deleted."
  echo "    Check versioning first — if it is enabled, previous versions may still be recoverable:"
  aws s3api get-bucket-versioning --bucket "$BUCKET" --query Status --output text 2>/dev/null
  echo "    Then delete the offending rule deliberately, after confirming it is not a cost control"
  echo "    someone owns: aws s3api delete-bucket-lifecycle --bucket $BUCKET"
fi
```

This step deliberately stops short of deleting the rule. A lifecycle policy on a log bucket is
frequently a legitimate cost control with an owner, and removing it silently converts a security
incident into a billing surprise.

#### Step 4 — Contain the principal

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

---

## 4. Eradication

### Remove Attacker Access

#### Establish whether the logs were lost or merely undelivered

The three causes differ sharply here and the report should not blur them.

- **Bucket policy blocked the write.** The events were never written anywhere. That period is gone.
- **KMS key disabled or deleted.** The objects exist. If the key was re-enabled in §3 Step 1 they
  are readable again and nothing was lost. If the key deletion completed, they are unreadable
  permanently — AWS cannot recover them and neither can you.
- **Bucket deleted, or lifecycle expired the objects.** The historical record is gone unless
  versioning was on, in which case previous versions may be recoverable.

Only the second has a good outcome available, and only if it was caught before the waiting period
expired.

#### Make the log bucket harder to break than the trail

The trail is protected by IAM and, ideally, an SCP. The bucket often is not, and the bucket is where
the evidence lives. Three changes close most of this:

- **Object Lock** in compliance mode on the log prefix, so objects cannot be deleted or overwritten
  before their retention expires — by anyone, including the account root.
- **Versioning**, so a delete leaves a recoverable previous version.
- **A bucket policy statement denying `s3:DeleteObject`, `s3:DeleteBucket`,
  `s3:PutLifecycleConfiguration` and `s3:PutBucketPolicy`** to everything except a named break-glass
  role.

#### Protect the KMS key as carefully as the bucket

A key policy denying `kms:DisableKey` and `kms:ScheduleKeyDeletion` outside a break-glass role
removes the sharpest version of this technique. Consider also lengthening the deletion waiting
period to the maximum of thirty days, which widens the window in which the scheduling alert can
still be acted on.

#### Deny the delivery-path operations outside a break-glass path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "ProtectTheAuditLogDeliveryPath",
  "Effect": "Deny",
  "Action": ["s3:DeleteBucket", "s3:PutLifecycleConfiguration", "s3:PutBucketPolicy",
             "s3:DeleteBucketPolicy", "kms:DisableKey", "kms:ScheduleKeyDeletion"],
  "Resource": "*",
  "Condition": {"ArnNotLike": {"aws:PrincipalARN": "arn:aws:iam::*:role/YourBreakGlassRole"}}
}
```

Attach it to an OU, not the management account, where SCPs do not apply. `YourBreakGlassRole` must
be a role that genuinely exists — an `ArnNotLike` against a non-existent role denies the action to
everyone including you. Note this statement is broad: it denies these actions on **every** bucket
and key, not only the audit ones, because SCPs cannot easily condition on resource identity across
accounts. Scope it with a `Resource` list if that is too wide, and test in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify delivery is working end to end

```bash
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  aws cloudtrail describe-trails --region "$R" --query 'trailList[].Name' --output text 2>/dev/null \
  | tr '\t' '\n' | while read -r T; do
      [ -z "$T" ] && continue
      aws cloudtrail get-trail-status --name "$T" --region "$R" --output json 2>/dev/null \
      | jq -r --arg t "$T" --arg r "$R" '
          if .IsLogging != true then "[FAIL] \($r)/\($t) not logging"
          elif ((.LatestDeliveryError // "") != "") then "[FAIL] \($r)/\($t) delivery failing: \(.LatestDeliveryError)"
          else "[OK] \($r)/\($t) delivering, last \(.LatestDeliveryTime // "unknown")" end'
    done
done | sort -u
```

#### Verify a freshly delivered object is readable

```bash
BUCKET="${1:?trail destination bucket required}"

# Delivery is not recovery. An object that arrives and cannot be decrypted is the KMS failure mode,
# and it looks identical to success in every metric.
LATEST="$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix AWSLogs/ \
           --query 'sort_by(Contents, &LastModified)[-1].Key' --output text 2>/dev/null)"
AGE_OK=$(aws s3api head-object --bucket "$BUCKET" --key "$LATEST" \
           --query 'LastModified' --output text 2>/dev/null)
echo "Newest object: ${LATEST:-none}  modified ${AGE_OK:-unknown}"

if [ -n "$LATEST" ] && [ "$LATEST" != "None" ] && aws s3 cp "s3://${BUCKET}/${LATEST}" /dev/null >/dev/null 2>&1; then
  echo "[OK] newest object is readable — delivery and decryption both work"
else
  echo "[FAIL] newest object is missing or unreadable — recovery is not complete"
fi
```

#### Verify the protections that make this fail next time

```bash
BUCKET="${1:?trail destination bucket required}"

aws s3api get-object-lock-configuration --bucket "$BUCKET" --output json 2>/dev/null \
| jq -r 'if .ObjectLockConfiguration.ObjectLockEnabled == "Enabled"
         then "[OK] Object Lock enabled" else "[FAIL] Object Lock not enabled" end' \
  || echo "[FAIL] Object Lock not configured — deleted log objects are unrecoverable"

aws s3api get-bucket-versioning --bucket "$BUCKET" --query Status --output text 2>/dev/null \
| while read -r V; do
    [ "$V" = "Enabled" ] && echo "[OK] versioning enabled" || echo "[FAIL] versioning is $V"
  done

aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" --output json 2>/dev/null \
| jq -r '[.Rules[] | select(.Status == "Enabled")] | length as $n
         | if $n == 0 then "[OK] no enabled lifecycle rules" else "[!] \($n) enabled lifecycle rule(s) — confirm each expiry is intended" end' \
  || echo "[OK] no lifecycle configuration"
```

#### Confirm the corrected detection fires

```bash
BUCKET="${1:?a NON-PRODUCTION bucket whose name matches your trail-bucket pattern}"

# Exercise the bucket-policy path rather than the key or the deletion: it is fully reversible and
# affects no real trail, while still exercising the destination-altered rule.
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$(jq -n --arg b "$BUCKET" '{
  Version: "2012-10-17",
  Statement: [{Sid: "DetectionTest", Effect: "Deny", Principal: "*", Action: "s3:DeleteBucket",
               Resource: "arn:aws:s3:::\($b)"}]}')" \
  && echo "[OK] policy written — expect the destination-altered rule within 15 min"

sleep 60
aws s3api delete-bucket-policy --bucket "$BUCKET" && echo "[OK] test policy removed"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Did AWS stop delivering, or did we stop receiving? | Entirely different teams and responses. If this took more than a few minutes to establish, the scheduled check is not reading `get-trail-status`. |
| Which of the four delivery-path causes was it? | Whether the logs are lost, undelivered, or merely unreadable depends on the answer, and so does whether anything can be recovered. |
| Was a key deletion scheduled, and how long was left? | This is the only cause with a hard deadline that passes silently. |
| Did the alert come from an event or from the two-hour silence? | If the events were available and nothing fired, the coverage gap is the finding rather than the incident. |
| Was Object Lock or versioning enabled on the log bucket? | Decides whether deleted or expired log objects were recoverable. |
| Was the log bucket protected as carefully as the trail? | Usually it is not, and it is where the evidence actually lives. |

### Recommended Guardrails

**Put the heartbeat in a scheduled check that reads `get-trail-status`.** An absence rule inside a
rule engine reports clean forever. The check must read `IsLogging`, `LatestDeliveryError` and
`LatestDeliveryTime` — the middle one is the only signal for this entire class of incident and
nothing emits it as an event.

**Protect the log bucket more strongly than the trail.** Object Lock, versioning, and a policy
denying deletion and lifecycle changes outside a break-glass role. The trail can be recreated; the
delivered logs cannot.

**Alert on `ScheduleKeyDeletion` for audit keys specifically.** It is the only step in this playbook
whose consequence arrives days later with no further warning.

**Group the heartbeat by trail, not by ingestion stream.** Stream-level grouping conflates a stopped
trail with a broken collector and a dormant account, and the benign causes dominate — which is how
a P1 becomes something people close without reading.

**Rate the causes above the symptom.** Every one of the delivery-path changes is an event available
immediately. Waiting two hours for silence to accumulate discards that.

### Technique Reference

**T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log.** Verified live at
https://attack.mitre.org/techniques/T1685/002/ on 2026-08-30.

AWS references relied on throughout, all verified 2026-08-30:

- CloudTrail concepts — trails, organization trails and delivery:
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
- `DeleteTrail` API reference, for the statement that deleting a trail leaves the bucket and its log
  files intact — which is why the bucket, not the trail, is where the historical record is at risk:
  https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html

Service-wide verified behaviour shared by every `cloudtrail.*` playbook is in
`../_ground-truth/cloudtrail.md`.

### Residual Risk

**The heartbeat itself can fail silently.** A scheduled check that stops running produces the same
output as a healthy estate: nothing. Whatever runs it needs its own liveness signal, or this
playbook's primary control has the exact defect it was written to correct.

**A completed key deletion is unrecoverable by anyone.** Once the waiting period expires, AWS cannot
decrypt the objects and neither can you. The alert on `ScheduleKeyDeletion` is the only opportunity,
and it is days before the consequence.

**The bucket and key matching is name-based.** The rules identify trail destinations by naming
convention and a populated list. A log bucket that follows neither is invisible to every rule here,
and the §1 inventory is the only thing that fixes it.

**A trail delivering to another account's bucket is only half visible.** Cross-account delivery is
common and supported, but the bucket-side events happen in the other account's CloudTrail. Unless
those logs are also collected, the policy and lifecycle rules here cover nothing for that trail.
