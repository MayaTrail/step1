# IR Playbook: KMS Key Scheduled for Deletion — irreversible destruction of every ciphertext under a key via `kms:ScheduleKeyDeletion`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Destructive impact (a customer managed KMS key is placed in `PendingDeletion`; it stops working immediately, and when the 7–30 day waiting period expires the key, its key material and all of its metadata are permanently deleted, taking with them the ability to decrypt everything ever encrypted under it) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **Critical.** This is the only use case in the KMS set where *doing nothing for long enough* produces permanent, unrecoverable data loss, and the minimum time in which that can happen is seven days. AWS is unambiguous: after deletion "you can no longer decrypt the data that was encrypted under that KMS key, which means that data becomes unrecoverable", and recreating the key with the same key material does **not** recover a symmetric key's ciphertexts. The source rule rates it **P3**. That is a scheduling error, not a severity disagreement: P3 means the alert can wait in a queue, and this alert has a countdown attached to it. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485, T1486 (the source maps T1486 alone — see the mapping note in §6) |
| Services in Scope | KMS, CloudTrail, IAM, Organizations (SCP), CloudWatch, and every service holding a resource encrypted under the key — S3, EBS, RDS, Secrets Manager, DynamoDB, EFS, Backup |

**What the technique does:** the actor calls `kms:ScheduleKeyDeletion` with a `KeyId` and,
optionally, `PendingWindowInDays`. KMS moves the key to `PendingDeletion`, returns
`responseElements.keyState` and a `deletionDate`, and stops serving every cryptographic
operation on that key from that moment. Nothing is destroyed yet. When the waiting period
expires — 7 to 30 days as the caller chose, 30 by default, and AWS warns the real deletion may
be up to 24 hours later still — AWS deletes the key, its key material, all associated metadata
and every alias that refers to it. Every ciphertext produced under that key becomes permanently
undecryptable, including the encrypted data keys that S3, EBS, RDS and Secrets Manager hold
alongside your data. The actor need do nothing else; the deletion completes on AWS's timer,
not theirs.

**Why this is potent — the usual reflexes look at the wrong clock.** A responder who treats this
as an availability incident checks whether anything is broken, finds the running fleet fine, and
de-prioritises it. AWS documents why the fleet is fine: the effect on data keys already issued
"is delayed until the KMS key is used again", so an attached EBS volume keeps serving disk I/O
from the data key resident in the Nitro hardware and produces no error at all. Nothing screams
for days. Meanwhile the two things that matter are both invisible from the alert. First the
deadline — the event's `deletionDate` is a human-formatted string and the authoritative date is
only in `DescribeKey`. Second, `PutKeyPolicy` is **permitted on a key that is pending deletion**,
so an actor can schedule the deletion and then rewrite the key policy to remove your
`kms:CancelKeyDeletion`; because a KMS key policy grants the account nothing implicitly, that
closes the only exit before you have noticed there was one.

**Detection thesis.** The discriminator is not any field that separates malicious from routine
— a decommission and an attack issue the identical call — it is that the event exists at all
inside a bounded window, so the rule's only job is to reach a human before the window closes
and it therefore ships with **no principal allowlist**; the one field that does carry intent is
`requestParameters.pendingWindowInDays`, because 30 is the default and a caller that explicitly
passes 7 has chosen to leave the defender the least time the API permits. The source rule
captures neither: it matches a lower-cased event name CloudTrail never writes, and it never
reads the waiting period.

**Tier.** Promoted to **Tier 1** on `07-TIERS.md` **test 4 — the evidence is destroyed by the
remediation window**: the key, its usage history, its grants and its aliases are deleted
together at the deadline, so the blast radius must be collected before it expires or it becomes
permanently uncollectable. **Test 2** also applies — the recovery has a one-way ordering
(`CancelKeyDeletion` returns the key to `Disabled`, and `EnableKey` fails if it runs first) and
a step that can be severed by the attacker (`PutKeyPolicy` on a pending-deletion key). **Test 3**
applies as well: nothing in the event names what was encrypted under the key, and AWS does not
store it.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

- **CloudTrail management events**, on by default, `eventSource: kms.amazonaws.com`. AWS logs
  **all** KMS operations. Cryptographic operations — `Decrypt`, `Encrypt`, `GenerateDataKey`
  and the rest — carry `"managementEvent": true` and `"eventCategory": "Management"` in AWS's
  own published examples, so `lookup-events` can answer "was this key in use". This is the
  opposite of a data-plane API and the distinction decides whether the blast-radius query in §2
  returns anything at all.
- **The per-trail KMS exclusion, and how to detect it.** `PutEventSelectors` with
  `ExcludeManagementEventSources` set to `kms.amazonaws.com` drops **every** KMS event from that
  trail. AWS: the setting "excludes all AWS KMS events; you cannot exclude particular AWS KMS
  events", and it "cannot recover AWS KMS events that occurred while the exclusion was
  effective". If KMS events are missing, look for a `PutEventSelectors` event carrying that
  attribute. Run `aws cloudtrail get-event-selectors` now, not during an incident.
- **Field shapes on `ScheduleKeyDeletion`.** `requestParameters.keyId` is caller-typed;
  `requestParameters.pendingWindowInDays` is **optional and absent when the default was taken**;
  `responseElements.keyId` is the normalised **key ARN**, flat; `responseElements.keyState` is
  `PendingDeletion` or `PendingReplicaDeletion`; `responseElements.deletionDate` is a
  **human-formatted string** (`"Apr 12, 2021 18:58:30 PM"` in AWS's example) and is **omitted**
  for `PendingReplicaDeletion`. `resources[].ARN` carries the key ARN with `resources[].type`
  of `AWS::KMS::Key`. **`KeyMetadata.DeletionDate` from `DescribeKey` is the only authoritative
  deadline** — AWS: "the actual waiting period might be up to 24 hours longer than the one you
  scheduled."
- **AWS's documented CloudWatch alarm for this exact condition.** A metric filter over the
  CloudTrail log group matching the error message fragment `is pending deletion`, alarmed to
  SNS. It fires when a person or application tries to *use* a key in the waiting period, and by
  design it does **not** fire on `CancelKeyDeletion`, `PutKeyPolicy` or `ListKeys`, which are
  all permitted in that state. Build it before you need it.

**Alerting (must be pre-configured)**

- **`ScheduleKeyDeletion` succeeding on a customer managed key → P0**
- **`ScheduleKeyDeletion` carrying an explicit `pendingWindowInDays` at or near the 7-day minimum → P0**
- **`DisableKey` followed by `ScheduleKeyDeletion` by the same principal inside an hour → P1**

**Response Tooling**

- AWS CLI v2 and `jq`. Every query below assumes both.
- **Break-glass responder credentials that are not the principal under investigation**, and —
  specific to this service — credentials whose access to the key does not depend on a key policy
  the actor can rewrite. In practice that means the account principal path: a key policy
  statement granting `arn:aws:iam::<account-id>:root` `kms:*`, which is AWS's own default and is
  the only thing that survives the deletion of every IAM user and role in the account.
- `tools/decode_policy_documents.py` for Query 4. Do not write a new policy parser: IAM accepts
  `Statement` as an object or an array and `Principal` as an object or the bare string `"*"`,
  and an unguarded sweep reports clean on exactly the statement it exists to find.
- A calendar entry, and this is not a joke — the deadline is days away, the incident changes
  hands across shifts, and the failure mode of this playbook is a handover that loses the
  countdown.

**Known IOC Baselines**

- The principals that legitimately decommission keys and the change-record format you will
  reconcile against. The rule deliberately has **no allowlist**, so reconciliation is the control.
- Your account ID as `arn:aws:iam::<account-id>:root` — the account principal whose presence in
  a key policy is what keeps a key administrable.
- The key ARNs that protect backups and snapshots. Destroying one of those is the difference
  between an outage and an unrecoverable estate, and no field on the event says which is which.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ScheduleKeyDeletion` succeeding on a customer managed key | CloudTrail (management) | T1485 |
| P0 | `ScheduleKeyDeletion` carrying an explicit `pendingWindowInDays` at or near the 7-day minimum | CloudTrail (management) | T1485 |
| P1 | `DisableKey` followed by `ScheduleKeyDeletion` by the same principal inside an hour | CloudTrail (management) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `PutKeyPolicy` on a key already in `PendingDeletion` — the cancel path being closed behind you | CloudTrail (management) | T1531 |
| P2 | `DisabledException` or `KMSInvalidStateException` whose `errorMessage` contains `is pending deletion` | CloudTrail (management) | T1485 |
| P2 | `ScheduleKeyDeletion` refused with `AccessDenied` — the caller decided to destroy a key and the policy held | CloudTrail (management) | T1485 |
| P3 | `DeleteAlias` on a key pending deletion (its only human-readable name removed), or `DeleteKey` — AWS's own event when the waiting period expires and the key is gone | CloudTrail (management) | T1485 |

### Detection Rule Quality Notes

One source rule, and it cannot match the event it describes.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `eventName:"schedulekeydeletion"` in lower case | Returns nothing, ever, on a case-sensitive field match — CloudTrail writes `ScheduleKeyDeletion`. The source set is internally inconsistent about this: its `PutKeyPolicy` rule is cased correctly while three others are not, so this is a defect and not a platform convention | `eventName: 'ScheduleKeyDeletion'`, and P0 rather than the source's P3 — P3 means the alert waits in a queue, and this alert has a countdown attached that can be as short as seven days |
| No success filter | A principal denied on twenty keys fires the identical alert as one that scheduled twenty for destruction. The work-list and the detection's count diverge at the worst possible moment | `success:` block with `errorCode: null`; denials tracked as their own P2 signal |
| Never reads `pendingWindowInDays` | The one field on the event that carries intent is discarded. A caller who chose the 7-day minimum — leaving the least response time the API allows — is indistinguishable from a decommission taking the 30-day default | Second rule document matching an explicit window of 7–10 days at `high` |
| No view of the disable-then-destroy sequence | The most diagnostic pattern in the service — an actor confirming nothing screams before making the irreversible call — is not detected by either half on its own | `temporal_ordered` correlation across `DisableKey` and `ScheduleKeyDeletion` by one principal inside an hour |
| Mapped to T1486 / *Data Encrypted for Impact* alone | Sends the responder hunting for attacker-encrypted data that does not exist. The data was already encrypted, by you; what is destroyed is the ability to reverse that | T1485 *Data Destruction* primary, T1486 retained as the second reading |

**Recommended detection — a customer managed KMS key scheduled for deletion.**

```yaml
# KMS Key Scheduled for Deletion (T1485 / T1486)
#
# THIS IS THE ONE KMS EVENT WITH A DEADLINE. `ScheduleKeyDeletion` moves the key to
# `PendingDeletion` and starts a waiting period of 7-30 days, default 30. During the window
# the key cannot be used in any cryptographic operation, and when the window expires AWS
# deletes the key, its key material, all of its metadata and every alias that refers to it.
# AWS: "After a KMS key is deleted, you can no longer decrypt the data that was encrypted
# under that KMS key, which means that data becomes unrecoverable." Re-importing the same
# key material does NOT recover a symmetric key's ciphertexts - AWS binds metadata unique to
# each KMS key into every ciphertext precisely so that it cannot be done.
#
# THE WINDOW IS THE ENTIRE RESPONSE OPPORTUNITY, AND `CancelKeyDeletion` IS THE WHOLE OF
# CONTAINMENT. It works at any point during the window and not one second after it. So the
# only thing this rule has to achieve is reaching a human while the window is open - which is
# why it fires on EVERY successful ScheduleKeyDeletion with no allowlist. A planned
# decommission firing this rule and being closed against a change record is the intended
# behaviour, not a false positive to tune away.
#
# THE SHORT-WINDOW RULE IS THE HIGH-CONFIDENCE ONE. 30 days is the default and is what every
# client that omits the parameter gets. A caller that explicitly passes 7 has chosen to give
# the defender the least time the API permits. That is a deliberate act with no operational
# benefit, and it is visible in `requestParameters.pendingWindowInDays`.
#
# ONLY CUSTOMER MANAGED KEYS REACH THIS EVENT. AWS: "You can only schedule the deletion of a
# customer managed key. You cannot delete AWS managed keys or AWS owned keys."
#
# THE SOURCE RULE matches `eventName:"schedulekeydeletion"` in lower case - not the form
# CloudTrail writes - with no success filter and nothing else, at P3. It has no view of the
# waiting period, which is the one field on the event that carries intent, and P3 for an
# event whose response window can be as short as seven days is a scheduling error.
title: KMS key scheduled for deletion
id: beec5d0e-bc09-4f65-abc9-7a8592293eac
name: kms_key_scheduled_deletion
status: experimental
description: >-
  A customer managed KMS key was scheduled for deletion. The key is unusable from this moment
  and is permanently destroyed when the waiting period expires, taking with it the ability to
  decrypt everything ever encrypted under it. CancelKeyDeletion reverses this during the
  window and not afterwards.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
  - attack.t1486
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'kms.amazonaws.com'
    eventName: 'ScheduleKeyDeletion'
  success:
    errorCode: null
  # No principal allowlist, deliberately, and this is the one rule in the KMS set that does
  # not carry one. The response window can be as short as seven days and CancelKeyDeletion is
  # the only remedy; a rule that suppresses the alert for an allowlisted role trades the
  # entire response opportunity for a quieter channel. Reconcile against the change record
  # instead of filtering in the rule.
  condition: selection and success
falsepositives:
  - >-
    A planned key decommission. Expected to fire, and expected to be closed against a change
    record naming the key ARN — that reconciliation is the control, not the rule.
level: high
---
# The waiting period is the only field on this event that carries intent. AWS accepts 7-30
# days and defaults to 30 when the parameter is omitted, so a caller that explicitly asks for
# 7 has chosen to leave the defender the shortest window the API allows. No allowlist and no
# success filter interaction: this fires alongside the rule above rather than instead of it.
#
# COVERAGE LIMIT, stated so it is not mistaken for a gap in the technique: pendingWindowInDays
# is an OPTIONAL request parameter. A caller that omits it gets 30 days and produces an event
# with no such field, so this rule sees explicit short windows only. The authoritative
# deadline is never this field — it is KeyMetadata.DeletionDate from DescribeKey, which AWS
# documents as being up to 24 hours later than the scheduled time.
title: KMS key scheduled for deletion with the shortest permitted waiting period
id: d0ffb086-be6e-4d93-aa6c-65a22bc15993
name: kms_key_scheduled_deletion_short_window
status: experimental
description: >-
  A KMS key was scheduled for deletion with an explicit waiting period at or near the 7-day
  minimum, against a documented default of 30. The caller chose to minimise the time available
  to notice and cancel.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'kms.amazonaws.com'
    eventName: 'ScheduleKeyDeletion'
  short_window:
    requestParameters.pendingWindowInDays:
      - 7
      - 8
      - 9
      - 10
  success:
    errorCode: null
  condition: selection and short_window and success
falsepositives:
  - >-
    A decommission pipeline that hard-codes the minimum window to release the key-count quota
    sooner. Real, and worth finding on its own merits — the pipeline should be using 30.
level: high
---
# Base rule — sequence component only, not for direct alerting. The disable is alerted on in
# its own right by ../../kms.impact.kms-key-disabled/detections/sigma_t1489.yml; this copy
# exists because a Sigma correlation resolves its base rules by `name:` within the SAME file
# (B8), so a rule referenced here must ship here. Kept at informational so it cannot page on
# its own, and carrying the same success filter as the correlation it feeds (D-f) — otherwise
# a DENIED disable followed by a legitimate deletion would fire the correlation `high`.
title: KMS key disabled (sequence component)
id: bfbbad1e-45b1-4bfa-8968-d44681088bf6
name: kms_key_disabled_component
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. A successful DisableKey, used
  as the first half of the disable-then-destroy sequence.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'kms.amazonaws.com'
    eventName: 'DisableKey'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# Disable, then destroy. An operator retiring a key does one or the other; an actor working
# through a key estate does both, because disabling first confirms that nothing screams before
# the irreversible call is made. One hour is generous on purpose — the pair is diagnostic
# whether it is seconds apart in a script or a working day apart in a deliberate campaign, and
# a longer timespan costs nothing because the second event is already `high` on its own.
#
# `temporal_ordered` conveys ordering by its type name. Do NOT add `ordered: true` (B7).
# Grouped by principal rather than by key: the same actor disabling key A and destroying key B
# is the same finding, and the key identifier on the request side is caller-typed anyway.
title: KMS key disabled and then scheduled for deletion by the same principal
id: 1eb3d632-f12c-4a28-affe-0b2051360e29
status: experimental
description: >-
  One principal disabled a KMS key and then scheduled a KMS key for deletion inside an hour.
  That is the destruction sequence — the reversible step used to confirm the ground before the
  irreversible one.
references:
  - https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
  - attack.t1486
correlation:
  type: temporal_ordered
  rules:
    - kms_key_disabled_component
    - kms_key_scheduled_deletion
  group-by:
    - userIdentity.arn
  timespan: 1h
level: high
```

The rule deliberately has no principal allowlist and will therefore fire on planned
decommissions — that is the design, not a defect, because the response window can be seven days
and a suppression that saves a page costs the entire opportunity to cancel. What the rule
cannot do is tell you what the key protected: nothing on the event names a single ciphertext,
and AWS states plainly that it "does not store this information and does not store any of the
ciphertexts". Queries 2 and 3 exist because that answer has to be assembled from three partial
sources before the deadline destroys all three.

---

### Key Investigation Queries

> KMS is regional and key ARNs are region-scoped — run every query per Region, and note that a multi-Region key has an independent replica in each Region with its own key state and its own deletion clock. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page**; the loops below page on `NextToken`.

#### Query 1 — Reconstruct: who scheduled which keys, with what waiting period, and what has been done since

```bash
REGION="<region>"; START="<ISO8601-start>"; END="<ISO8601-end>"

for EN in ScheduleKeyDeletion CancelKeyDeletion DisableKey EnableKey PutKeyPolicy DeleteAlias; do
  TOKEN=""
  while : ; do
    PAGE=$(aws cloudtrail lookup-events --region "$REGION" --output json --max-results 50 \
             --lookup-attributes AttributeKey=EventName,AttributeValue="$EN" \
             --start-time "$START" --end-time "$END" ${TOKEN:+--next-token "$TOKEN"} 2>&1)
    if ! printf '%s' "$PAGE" | jq -e 'has("Events")' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $EN — lookup-events returned no Events key: $PAGE"; break
    fi
    printf '%s' "$PAGE" | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.eventSource == "kms.amazonaws.com")
      | {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
         akid: (.userIdentity.accessKeyId // "none"),
         ip: .sourceIPAddress, agent: .userAgent,
         err: (.errorCode // "none"), msg: (.errorMessage // "-"),
         keyArn: (.responseElements.keyId
                  // ([.resources[]?.ARN] | map(select(. != null)) | first)
                  // .requestParameters.keyId // "unknown"),
         windowDays: (.requestParameters.pendingWindowInDays // "default-30"),
         keyState: (.responseElements.keyState // "-"),
         deletionDateAsLogged: (.responseElements.deletionDate // "-"),
         policyName: (.requestParameters.policyName // "-")}'
    TOKEN=$(printf '%s' "$PAGE" | jq -r '.NextToken // empty'); [ -n "$TOKEN" ] || break
  done
done
```

Read it as a timeline per `keyArn`. `windowDays` of `default-30` means the caller omitted the
parameter and took the documented default — an explicit `7` is the finding, because the caller
chose the shortest window AWS permits. `keyState` of `PendingReplicaDeletion` means a
multi-Region primary that still has replicas: it has **no** deletion date and can sit there
indefinitely, and the real work is in the replica Regions. A `PutKeyPolicy` row whose `time` is
**after** a `ScheduleKeyDeletion` row on the same `keyArn` is the highest-value line in the
output — go to Query 4 before anything else. `keyArn`, `caller` and `akid` feed every step
below.

#### Query 2 — The deadline board: every key currently pending deletion, with the authoritative date

```bash
REGION="<region>"

KEYS=$(aws kms list-keys --region "$REGION" --output json 2>&1)
if ! printf '%s' "$KEYS" | jq -e 'has("Keys")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — list-keys failed; there is no clean result below: $KEYS"
else
  for KID in $(printf '%s' "$KEYS" | jq -r '.Keys[].KeyId'); do
    META=$(aws kms describe-key --region "$REGION" --key-id "$KID" --output json 2>&1)
    if ! printf '%s' "$META" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $KID — describe-key returned no KeyState: $META"; continue
    fi
    printf '%s' "$META" | jq -r '.KeyMetadata
      | select(.KeyState == "PendingDeletion" or .KeyState == "PendingReplicaDeletion")
      | "[!] " + .Arn
        + "  state=" + .KeyState
        + "  manager=" + (.KeyManager // "unknown")
        + "  multiRegion=" + ((.MultiRegion // false) | tostring)
        + "  deletionDate=" + ((.DeletionDate // "NONE-multi-region-primary") | tostring)
        + "  pendingWindow=" + ((.PendingDeletionWindowInDays // "n/a") | tostring)'
  done
  echo "[i] sweep complete for $REGION — repeat for every enabled Region"
fi
```

`DescribeKey` is permitted in **every** key state, so this sweep works on exactly the keys that
are hardest to see elsewhere. Each `[!]` line is a key on a countdown; `DeletionDate` here is
authoritative and already includes the up-to-24-hour margin AWS warns about, unlike anything in
the event. A `deletionDate` of `NONE-multi-region-primary` is a primary key whose clock has not
started and will not start until its last replica is deleted — check the replica Regions, do not
mark it safe. Work the board in ascending `deletionDate` order, not in alert order.

#### Query 3 — Blast radius: what this key was actually protecting, before the answer is deleted with it

```bash
REGION="<region>"; KEY_ARN="<key-arn-from-Query-1>"; START="<ISO8601-start>"; END="<ISO8601-end>"

# 3a. Last recorded cryptographic use. An EMPTY KeyLastUsage is NOT proof of non-use.
LU=$(aws kms get-key-last-usage --region "$REGION" --key-id "$KEY_ARN" --output json 2>&1)
if ! printf '%s' "$LU" | jq -e 'has("TrackingStartDate")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — get-key-last-usage failed: $LU"
else
  printf '%s' "$LU" | jq -r '
    if ((.KeyLastUsage.Operation // "") != "") then
      "[!] IN USE — last " + .KeyLastUsage.Operation
        + " at " + (.KeyLastUsage.Timestamp|tostring)
        + ", CloudTrail event " + (.KeyLastUsage.CloudTrailEventId // "unknown")
    elif (.KeyCreationDate >= .TrackingStartDate) then
      "[i] no cryptographic use since creation — created " + (.KeyCreationDate|tostring)
        + " >= tracking start " + (.TrackingStartDate|tostring)
    else
      "[!] INCONCLUSIVE — key predates usage tracking (created " + (.KeyCreationDate|tostring)
        + " < tracking start " + (.TrackingStartDate|tostring)
        + "); CloudTrail is the only authority"
    end'
fi

# 3b. What asked for data keys under this key. For SSE-KMS the encryption context names the
# object: AWS's own example carries {"aws:s3:arn": "arn:aws:s3:::bucket/object"}.
for EN in GenerateDataKey Decrypt Encrypt; do
  TOKEN=""
  while : ; do
    PAGE=$(aws cloudtrail lookup-events --region "$REGION" --output json --max-results 50 \
             --lookup-attributes AttributeKey=EventName,AttributeValue="$EN" \
             --start-time "$START" --end-time "$END" ${TOKEN:+--next-token "$TOKEN"} 2>&1)
    if ! printf '%s' "$PAGE" | jq -e 'has("Events")' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $EN — lookup-events returned no Events key: $PAGE"; break
    fi
    printf '%s' "$PAGE" | jq -r --arg key "$KEY_ARN" '.Events[].CloudTrailEvent | fromjson
      | select(any(.resources[]?.ARN // ""; . == $key))
      | {time: .eventTime, op: .eventName, caller: .userIdentity.arn,
         invokedBy: (.userIdentity.invokedBy // "direct"),
         err: (.errorCode // "none"),
         context: (.requestParameters.encryptionContext // {})}'
    TOKEN=$(printf '%s' "$PAGE" | jq -r '.NextToken // empty'); [ -n "$TOKEN" ] || break
  done
done

# 3c. The aliases and grants that are deleted with the key.
aws kms list-aliases --region "$REGION" --key-id "$KEY_ARN" --output json 2>&1 | head -c 4000
aws kms list-grants  --region "$REGION" --key-id "$KEY_ARN" --output json 2>&1 | head -c 4000
```

3b is keyed on `resources[].ARN`, **not** `requestParameters.keyId`: AWS's own published example
of an S3-initiated `Decrypt` carries no `keyId` in `requestParameters` at all — only the
encryption context — so a request-parameter match drops every service-initiated use of the key,
which is most of it. Add `GenerateDataKeyWithoutPlaintext` and the pair-generating calls if the
key serves EBS or an asymmetric workload. `invokedBy` of `internal.amazonaws.com` marks a call
an AWS service made for you and is the fastest route from key to dependent service. Distinct
`context` values are the nearest thing to an inventory that exists; treat them as a floor.

#### Query 4 — Can you still cancel? Inspect the live key policy before you rely on it

```bash
REGION="<region>"; KEY_ARN="<key-arn-from-Query-1>"

OWN=$(aws sts get-caller-identity --query Account --output text 2>&1)
printf '%s' "$OWN" | grep -qE '^[0-9]{12}$' \
  || echo "[!] account id unresolved ($OWN) — the verdict below is unreliable"

# GetKeyPolicy is permitted on a key in PendingDeletion, so this works when it matters most.
# `default` is the only valid policy name KMS accepts.
POL=$(aws kms get-key-policy --region "$REGION" --key-id "$KEY_ARN" \
        --policy-name default --output json 2>&1)
if ! printf '%s' "$POL" | jq -e '.Policy' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — cannot read the key policy: $POL"
else
  # WHO holds the key, via the shared decoder — it guards Statement object-or-array and
  # Principal object-or-bare-string, which an ad-hoc jq sweep gets wrong in the direction
  # that reports clean.
  printf '%s' "$POL" | jq -c --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg k "$KEY_ARN" \
      '{time: $t, caller: "live-key-policy", grantee: $k, policy_name: "default", doc: .Policy}' \
    | ORG_ACCOUNTS="$OWN" python3 tools/decode_policy_documents.py

  # WHETHER THE ACCOUNT PRINCIPAL STILL HOLDS kms:*, which is what keeps the key administrable.
  # Statement may be an object OR an array; Principal an object OR the bare string "*";
  # Principal.AWS and Action a string OR an array. All four are normalised before use.
  # A statement MISSING Resource or Action has NO EFFECT even though the API accepted it —
  # AWS documents exactly that — so those statements are dropped rather than counted.
  ROOT_OK=$(printf '%s' "$POL" | jq -r --arg acct "$OWN" '
    (.Policy | fromjson) as $d
    | [ ($d.Statement // [] | if type == "object" then [.] else . end)[]
        | select(type == "object")
        | select(has("Resource") and has("Action"))
        | select(.Effect == "Allow")
        | ((.Principal // {}) | if type == "string" then {AWS: [.]} else . end) as $p
        | (($p.AWS // []) | if type == "string" then [.] else . end) as $aws
        | ((.Action // []) | if type == "string" then [.] else . end) as $acts
        | select(any($aws[]; . == ("arn:aws:iam::" + $acct + ":root") or . == $acct or . == "*"))
        | select(any($acts[]; . == "kms:*" or . == "*" or . == "kms:CancelKeyDeletion"))
      ] | length' 2>&1)
  if ! printf '%s' "$ROOT_OK" | grep -qE '^[0-9]+$'; then
    echo "[!] INCONCLUSIVE — the key policy did not parse: $ROOT_OK"
  elif [ "$ROOT_OK" -gt 0 ]; then
    echo "[OK] the account principal retains an effective grant covering kms:CancelKeyDeletion"
  else
    echo "[FAIL] NO effective statement grants the account principal kms:CancelKeyDeletion."
    echo "       You may not be able to cancel this deletion. Fix the key policy FIRST —"
    echo "       see ../kms.impact.key-policy-access-removed/PLAYBOOK.md — and if no"
    echo "       principal at all can write the policy, open an AWS Support case now: AWS"
    echo "       documents Support as the only route back into an unmanageable key."
  fi
fi
```

The decoder answers *who* — any `[!] EXTERNAL` or `[!] PUBLIC` line means the key policy now
names a principal outside your account, which is a separate incident on top of this one. The
`ROOT_OK` test answers the only question that governs the next fifteen minutes: whether a
statement that is both **present and effective** still grants the account principal a permission
covering `kms:CancelKeyDeletion`. It is written to drop statements missing `Resource` or
`Action` because AWS documents that such a statement has no effect while the API call that
stored it still succeeds — so a policy can contain the string `:root` and grant nothing, and a
`grep` for `:root` would report clean over a locked key.

#### Query 5 — Session reconstruction: everything that principal did

```bash
REGION="<region>"; AKID="<access-key-id-from-Query-1>"; START="<ISO8601-start>"; END="<ISO8601-end>"

TOKEN=""
while : ; do
  PAGE=$(aws cloudtrail lookup-events --region "$REGION" --output json --max-results 50 \
           --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$AKID" \
           --start-time "$START" --end-time "$END" ${TOKEN:+--next-token "$TOKEN"} 2>&1)
  if ! printf '%s' "$PAGE" | jq -e 'has("Events")' >/dev/null 2>&1; then
    echo "[!] INCONCLUSIVE — lookup-events returned no Events key: $PAGE"; break
  fi
  printf '%s' "$PAGE" | jq -r '.Events[].CloudTrailEvent | fromjson
    | {time: .eventTime, source: .eventSource, event: .eventName,
       caller: .userIdentity.arn, ip: .sourceIPAddress,
       err: (.errorCode // "none")}'
  TOKEN=$(printf '%s' "$PAGE" | jq -r '.NextToken // empty'); [ -n "$TOKEN" ] || break
done
```

Key on the **access key ID**, not a user name: `AttributeKey=Username` matches the session name,
which for a role session is not the role name and for an instance-profile session is the
instance ID. Read the whole session — `cloudtrail:PutEventSelectors`, `iam:CreateAccessKey` or
`s3:PutBucketPolicy` in the same session change what incident this is.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The order here is load-bearing and one-way. **Confirm you can still administer the key before
anything else** — `PutKeyPolicy` is permitted on a key pending deletion, so the actor may have
closed the exit behind them. Then cancel the deletion; that is the whole of containment and it
works at any point in the window and not one second after. Then, and only then, re-enable:
`CancelKeyDeletion` returns the key to **`Disabled`**, not `Enabled`, and `EnableKey` **fails**
with `KMSInvalidStateException` if it runs before the cancel.

> Run under the **break-glass responder credentials** from §1 — and specifically not under any
> principal whose access to this key depends on a key policy the actor was able to rewrite.

#### Step 1 — Confirm the cancel path is open

Run **Query 4** now, before Step 2. If it prints `[FAIL] NO effective statement grants the
account principal kms:CancelKeyDeletion`, the containment below will be refused with
`AccessDenied` and the response is a key-policy repair, not a cancel — go to
`../kms.impact.key-policy-access-removed/PLAYBOOK.md`, restore the account-principal statement
with `PutKeyPolicy`, and come back. If **no** principal can write the key policy, open an AWS
Support case in this step rather than after the deadline: AWS documents Support as the only
route back into a key nobody can administer, and that route takes time you are already spending.

#### Step 2 — Cancel the deletion

```bash
REGION="<region>"; KEY_ARN="<key-arn-from-Query-1>"

META=$(aws kms describe-key --region "$REGION" --key-id "$KEY_ARN" --output json 2>&1)
if ! printf '%s' "$META" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — cannot read the key state; do not act blind: $META"
else
  STATE=$(printf '%s' "$META" | jq -r '.KeyMetadata.KeyState')
  case "$STATE" in
    PendingDeletion|PendingReplicaDeletion)
      if aws kms cancel-key-deletion --region "$REGION" --key-id "$KEY_ARN"; then
        echo "[OK] cancel-key-deletion accepted — the key is now DISABLED, not enabled."
        echo "     It is saved from destruction and still refuses every cryptographic"
        echo "     operation. Step 3 is not optional."
      else
        echo "[FAIL] cancel-key-deletion was refused. AccessDenied means the key policy no"
        echo "       longer grants you kms:CancelKeyDeletion — go back to Step 1."
      fi ;;
    Enabled|Disabled)
      echo "[!] $KEY_ARN is $STATE, not pending deletion. cancel-key-deletion would be"
      echo "    rejected with KMSInvalidStateException. Either it was already cancelled —"
      echo "    find out by whom in Query 1 — or you are on the wrong key." ;;
    *)
      echo "[!] INCONCLUSIVE — state is $STATE; establish why before acting" ;;
  esac
fi
```

#### Step 3 — Re-enable the key

```bash
REGION="<region>"; KEY_ARN="<key-arn-from-Query-1>"

META=$(aws kms describe-key --region "$REGION" --key-id "$KEY_ARN" --output json 2>&1)
if ! printf '%s' "$META" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — cannot read the key state: $META"
else
  STATE=$(printf '%s' "$META" | jq -r '.KeyMetadata.KeyState')
  case "$STATE" in
    Disabled)
      if aws kms enable-key --region "$REGION" --key-id "$KEY_ARN"; then
        echo "[OK] enable-key accepted — the key is usable again"
      else
        echo "[FAIL] enable-key was refused; read the error before retrying"
      fi ;;
    PendingDeletion|PendingReplicaDeletion)
      echo "[FAIL] still $STATE — enable-key CANNOT succeed in this state. Step 2 did not"
      echo "       take effect. Do not proceed; the clock is still running." ;;
    Enabled)
      echo "[OK] $KEY_ARN is already Enabled" ;;
    *)
      echo "[!] INCONCLUSIVE — state is $STATE" ;;
  esac
fi
```

#### Step 4 — Contain the principal

```bash
CALLER="<caller-from-Query-1>"
FREEZE='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["kms:ScheduleKeyDeletion","kms:DisableKey","kms:PutKeyPolicy","kms:DeleteImportedKeyMaterial","kms:DeleteAlias","kms:DisableKeyRotation","kms:RetireGrant","kms:RevokeGrant"],"Resource":"*"}]}'

case "$CALLER" in
  *":user/"*)          # IAM user: the name is $NF. Disable keys before attaching the deny.
    UNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$UNAME" \
                 --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$UNAME" --access-key-id "$K" --status Inactive
    done
    if aws iam put-user-policy --user-name "$UNAME" --policy-name IR-KMS-Destroy-Freeze \
         --policy-document "$FREEZE"; then
      echo "[OK] contained IAM user $UNAME"
    else
      echo "[FAIL] could not attach IR-KMS-Destroy-Freeze to user $UNAME — contain manually"
    fi ;;
  *":assumed-role/"*)  # Role name is the 2nd '/' segment; $NF is the SESSION name.
    RNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $2}')
    if aws iam put-role-policy --role-name "$RNAME" --policy-name IR-KMS-Destroy-Freeze \
         --policy-document "$FREEZE"; then
      echo "[OK] contained IAM role $RNAME"
    else
      echo "[FAIL] could not attach IR-KMS-Destroy-Freeze to role $RNAME — contain manually"
    fi ;;
  *)
    echo "[!] $CALLER is root, federated or a service principal — contain manually." ;;
esac
```

An IAM `Deny` bites even where the key policy is what grants access: AWS states that without the
account-principal statement "IAM policies that allow access to the key are ineffective, although
IAM policies that deny access to the key are still effective". The deny includes
`kms:DeleteImportedKeyMaterial` because on a key with imported material that call makes the key
unusable **immediately, with no waiting period at all** — the faster destructive path a contained
actor reaches for next.

#### Step 5 — Sweep every Region before you stand down

Re-run **Query 2** in every enabled Region. The alert fired on one key; `list-keys` is
per-Region, a multi-Region primary's replicas each carry their own key state and their own
clock, and a key whose deletion was scheduled before your query window opened will not appear in
Query 1 at all. Query 2 reads live state and is the only enumeration that cannot miss one.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm every key in the account is off the clock

Query 2 in every Region, with the count asserted rather than eyeballed — the assertion is in §5.
A single missed key is a total loss of whatever it protected, so this is not a spot check.

#### Remove the other destructive persistence by the same principal

From Query 5's session reconstruction, in order of how long each outlives your containment:

- **`PutKeyPolicy`** on any key — see `../kms.impact.key-policy-access-removed/PLAYBOOK.md`. A
  rewritten key policy survives the deletion of the acting principal and is the one artefact
  that can make a key permanently unmanageable.
- **`CreateGrant`** — a grant is an independent grant of key permissions that does not appear in
  the key policy at all. `aws kms list-grants --key-id "$KEY_ARN"` and
  `aws kms revoke-grant --key-id "$KEY_ARN" --grant-id <id>` for anything unrecognised.
- **`DeleteImportedKeyMaterial`** on a key with `Origin: EXTERNAL` — immediate, no waiting
  period, and reversible only by re-importing material you may not hold.
- **`DeleteAlias`** — removes the key's only human-readable name, which every runbook and
  application reference uses. Recreate it with `aws kms create-alias`. **`DisableKeyRotation`**
  in the same session is quieter and points at long-term key compromise rather than destruction.
- **`cloudtrail:PutEventSelectors`** — if the actor excluded `kms.amazonaws.com` from a trail,
  every KMS query above has been reading an incomplete record. Check it explicitly.

#### Right-size the permission that made this possible

`kms:ScheduleKeyDeletion` belongs to key administration and to no runtime workload. AWS's own
default key policy separates key **administrators** from key **users** for exactly this reason,
and it offers a console toggle — *Allow key administrators to delete this key* — that removes
`kms:ScheduleKeyDeletion` and `kms:CancelKeyDeletion` from the administrator statement
altogether. Take it for any key protecting data you cannot lose. Then apply the condition-key
guardrails in §6.

#### Remove the emergency policies once the account is clean

Containment could have attached the deny to a user **or** a role, so check both paths and assert
the result rather than assuming it:

```bash
CALLER="<caller-from-Query-1>"
case "$CALLER" in
  *":user/"*)         NAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $NF}')
                      aws iam delete-user-policy --user-name "$NAME" \
                        --policy-name IR-KMS-Destroy-Freeze
                      LEFT=$(aws iam list-user-policies --user-name "$NAME" --output json 2>&1) ;;
  *":assumed-role/"*) NAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $2}')
                      aws iam delete-role-policy --role-name "$NAME" \
                        --policy-name IR-KMS-Destroy-Freeze
                      LEFT=$(aws iam list-role-policies --role-name "$NAME" --output json 2>&1) ;;
  *)                  NAME=""; LEFT="" ;;
esac
if [ -z "$NAME" ]; then
  echo "[!] INCONCLUSIVE — $CALLER is not an IAM user or assumed role; check by hand"
elif ! printf '%s' "$LEFT" | jq -e 'has("PolicyNames")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — could not re-list inline policies for $NAME: $LEFT"
elif printf '%s' "$LEFT" | jq -e '.PolicyNames | index("IR-KMS-Destroy-Freeze")' >/dev/null 2>&1; then
  echo "[FAIL] IR-KMS-Destroy-Freeze is still attached to $NAME"
else
  echo "[OK] IR-KMS-Destroy-Freeze removed from $NAME"
fi
```

---

## 5. Recovery

### Restore Clean State

#### Verify the key is Enabled — not merely "not pending deletion"

```bash
REGION="<region>"; KEY_ARN="<key-arn-from-Query-1>"

# The signal survives the remediation: DescribeKey is permitted in EVERY key state, so this
# check can still return PendingDeletion or Disabled after the cancel and the enable ran.
# [FAIL] is reachable, not zero by construction.
META=$(aws kms describe-key --region "$REGION" --key-id "$KEY_ARN" --output json 2>&1)
if ! printf '%s' "$META" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — describe-key returned no KeyState; NOT certified: $META"
else
  STATE=$(printf '%s' "$META" | jq -r '.KeyMetadata.KeyState')
  ENABLED=$(printf '%s' "$META" | jq -r '.KeyMetadata.Enabled')
  DDATE=$(printf '%s' "$META" | jq -r '.KeyMetadata.DeletionDate // "none"')
  case "$STATE" in
    Enabled)
      if [ "$ENABLED" = "true" ] && [ "$DDATE" = "none" ]; then
        echo "[OK] $KEY_ARN Enabled, Enabled=true, no DeletionDate — recovered"
      else
        echo "[!] INCONCLUSIVE — KeyState=Enabled but Enabled=$ENABLED DeletionDate=$DDATE"
      fi ;;
    Disabled)
      echo "[FAIL] $KEY_ARN is Disabled. The deletion was cancelled and the key was NOT"
      echo "       re-enabled — this is the exact state CancelKeyDeletion leaves behind."
      echo "       Run Containment Step 3." ;;
    PendingDeletion|PendingReplicaDeletion)
      echo "[FAIL] $KEY_ARN is $STATE, DeletionDate=$DDATE. The clock is still running." ;;
    *)
      echo "[!] INCONCLUSIVE — KeyState=$STATE is neither recovered nor a known failure" ;;
  esac
fi
```

Three outcomes, three verdicts, and the `Disabled` branch is the reason this is written out
rather than tested as "not `PendingDeletion`". `CancelKeyDeletion` leaves the key **`Disabled`**
by design; a check that treats anything other than `PendingDeletion` as clean certifies a dead
key as recovered, and the responder closes the incident with the workload still down.

#### Verify no key anywhere in this Region is still on a deletion clock

```bash
REGION="<region>"

KEYS=$(aws kms list-keys --region "$REGION" --output json 2>&1)
if ! printf '%s' "$KEYS" | jq -e 'has("Keys")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — list-keys failed; the Region is NOT certified clean: $KEYS"
else
  PENDING=0; UNREAD=0
  for KID in $(printf '%s' "$KEYS" | jq -r '.Keys[].KeyId'); do
    META=$(aws kms describe-key --region "$REGION" --key-id "$KID" --output json 2>&1)
    if ! printf '%s' "$META" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
      UNREAD=$((UNREAD + 1)); echo "[!] unreadable: $KID"; continue
    fi
    ST=$(printf '%s' "$META" | jq -r '.KeyMetadata.KeyState')
    case "$ST" in
      PendingDeletion|PendingReplicaDeletion)
        PENDING=$((PENDING + 1))
        printf '%s' "$META" | jq -r '"[FAIL] still pending: " + .KeyMetadata.Arn
                                     + " deletionDate=" + ((.KeyMetadata.DeletionDate // "none")|tostring)' ;;
    esac
  done
  if [ "$UNREAD" -gt 0 ]; then
    echo "[!] INCONCLUSIVE — $UNREAD key(s) could not be read; $REGION is NOT certified clean"
  elif [ "$PENDING" -eq 0 ]; then
    echo "[OK] no key in $REGION is pending deletion"
  else
    echo "[FAIL] $PENDING key(s) in $REGION are still pending deletion"
  fi
fi
```

An unreadable key is neither clean nor pending — it is a call that did not run, and counting it
in an all-clear is how a Region gets certified with a key still on the clock. Repeat per Region.
Run this before closing, not once: a second `ScheduleKeyDeletion` can land while you work.

#### Verify the key policy still keeps the key administrable

Re-run **Query 4**. `[OK] the account principal retains an effective grant covering
kms:CancelKeyDeletion` is the pass condition. This is a real assertion after the remediation
because `GetKeyPolicy` is permitted in every key state and the policy is not touched by
`CancelKeyDeletion` or `EnableKey` — nothing about the recovery can manufacture a pass here.

#### Confirm the corrected detection fires

```bash
echo 'MUST fire on:     eventSource=kms.amazonaws.com, eventName=ScheduleKeyDeletion,'
echo '                  no errorCode — with or without requestParameters.pendingWindowInDays'
echo 'MUST ALSO fire the short-window rule on: requestParameters.pendingWindowInDays = 7'
echo 'MUST NOT fire the short-window rule on:  pendingWindowInDays = 30, or the field absent'
echo '                  (absent means the caller took the documented 30-day default)'
echo 'MUST NOT fire on: eventName=ScheduleKeyDeletion carrying errorCode=AccessDenied —'
echo '                  denials are the separate P2 signal, so probing is never counted as'
echo '                  destruction'
echo 'MUST NOT fire on: eventName=CancelKeyDeletion — that is the remedy, not the attack'
echo 'CORRELATION fires on: DisableKey then ScheduleKeyDeletion, same userIdentity.arn,'
echo '                  inside one hour, in that order. The reverse order must NOT fire it.'
echo 'EXPECTED FP, by design: every planned key decommission. The rule ships with NO principal'
echo '                  allowlist because the response window can be seven days; reconcile'
echo '                  against the change record instead of suppressing the alert.'
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A single API call put a production key on an irreversible countdown | `kms:ScheduleKeyDeletion` was reachable on `Resource: "*"` by a principal outside key administration, and no `kms:TrailingDaysWithoutKeyUsage` condition refused it for a key in active use |
| Nothing broke for days, so the incident was triaged as low urgency, and the deadline was read from the alert rather than from the key | Priority was taken from observed impact rather than from the deadline. AWS documents that data keys already issued keep working until next use, so "nothing is failing" is the expected state during the window. And `responseElements.deletionDate` is a human-formatted string up to 24 hours earlier than the real date — only `DescribeKey` carries the authoritative `KeyMetadata.DeletionDate`, and no runbook step required reading it |
| What the key protected could not be established from the event | Nothing in CloudTrail enumerates ciphertexts and AWS does not store them. The inventory had to be reassembled from `GetKeyLastUsage`, encryption contexts and grants — all of which are deleted with the key at the deadline |
| The cancel path depended on a key policy the actor could still rewrite | `PutKeyPolicy` is permitted on a key that is pending deletion, and a KMS key policy grants the account nothing implicitly. No control required the account-principal statement to be present and effective |
| No alarm existed on attempted use of a key pending deletion | AWS publishes a CloudWatch metric-filter alarm for exactly this — the `is pending deletion` error message — and it had not been built |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Key policy statement (a KMS key policy is a complete document — this is one statement of it,
// and it sits ALONGSIDE the "Enable IAM User Permissions" account-principal statement, never
// instead of it: a KMS key policy grants the account NOTHING implicitly). The same statement
// is valid in an SCP, and an SCP is reachable for this technique because the actor is a
// principal inside your own organisation — unlike an externally initiated resource-policy
// abuse, where only an RCP applies. Note that RCPs do not apply to AWS managed keys at all.
//
// FAILURE DIRECTION, and it fails OPEN: kms:TrailingDaysWithoutKeyUsage is derived from the
// same last-usage tracking as GetKeyLastUsage, so for a key with no recorded cryptographic use
// the condition key is absent from the request context, a plain NumericLessThan does not
// match, and the Deny DOES NOT APPLY. That is deliberate — retiring a never-used key is the
// case you want to allow. Do NOT "harden" it to NumericLessThanIfExists: that inverts the
// intent and blocks the legitimate retirement of unused keys.
{ "Sid": "DenyDeletionOfRecentlyUsedKeys", "Effect": "Deny",
  "Principal": "*",
  "Action": ["kms:ScheduleKeyDeletion", "kms:DisableKey"],
  "Resource": "*",
  "Condition": { "NumericLessThan": { "kms:TrailingDaysWithoutKeyUsage": "90" } } }
```

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Force the full 30-day waiting period, so the response window can never be shortened to 7.
// FAILURE DIRECTION: this Deny applies only when the caller SPECIFIES a window below 30. A
// caller that omits PendingWindowInDays takes the documented 30-day default, the condition key
// is absent from the request context and the Deny does not apply — the intended outcome, since
// 30 is already the maximum. It constrains how FAST a key can be destroyed, not whether it can.
{ "Sid": "RequireMaximumDeletionWindow", "Effect": "Deny",
  "Principal": "*",
  "Action": "kms:ScheduleKeyDeletion",
  "Resource": "*",
  "Condition": { "NumericLessThan": { "kms:ScheduleKeyDeletionPendingWindowInDays": "30" } } }
```

**Structural controls**

- **Separate key administration from key use, and take the deletion permission away from both.**
  AWS's console offers *Allow key administrators to delete this key* as a toggle; clearing it
  removes `kms:ScheduleKeyDeletion` and `kms:CancelKeyDeletion` from the administrators
  statement. For any key protecting data you cannot lose, deletion should require a deliberate
  key-policy change first — which is itself an alertable event.
- **Keep the account-principal statement in every key policy.** It is AWS's default for a
  reason: the account root is the only principal that cannot be deleted, and without that
  statement a key becomes unmanageable the moment its named principals are gone, with AWS
  Support as the only route back.
- **Never exclude `kms.amazonaws.com` from a trail.** It is all-or-nothing, the excluded period
  is unrecoverable, and it removes the only record of who used a key before it was destroyed.

**Detection improvements**

- Build AWS's documented CloudWatch alarm on the `is pending deletion` error message — the only
  signal that a key on the clock is still needed. It cannot see use of a downloaded public key
  outside AWS at all.
- Alert on `PutKeyPolicy` where the target key is in `PendingDeletion` — the combination is the
  cancel path being closed and no single-event rule expresses it, which is why it lives in
  `detections/kql_t1485.kql` rather than in the Sigma.
- Feed the deadline into the ticket, and alert on `DeleteKey` — AWS's own event when the window
  expires. `DeleteKey` is not a detection opportunity but the record that the window was missed:
  an alert that pages once and then sits in a queue is this technique's documented failure mode.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction (Impact). Second reading T1486 — Data Encrypted for Impact, which is the source's mapping. T1490 — Inhibit System Recovery applies where the destroyed key protects backups |
| MITRE tactic | Impact (TA0040) |
| Primary API | `kms:ScheduleKeyDeletion` → `PendingDeletion` → AWS-initiated `DeleteKey` at expiry. Reversed **only** by `kms:CancelKeyDeletion`, and only during the window |
| Event source | `kms.amazonaws.com`, **management** plane, on by default — verified against AWS's published `ScheduleKeyDeletion` CloudTrail examples, which carry `"managementEvent": true` and `"eventCategory": "Management"` |
| Key discriminator | The existence of the event inside a bounded window — a decommission and an attack issue the identical call. The only field carrying intent is `requestParameters.pendingWindowInDays`: 30 is the default, 7 is the minimum, and an explicit 7 is a choice to minimise your response time |
| Ground-truth signal | `responseElements.keyId` (key ARN) and `responseElements.keyState`; `resources[].ARN` on every KMS event. The authoritative deadline is `KeyMetadata.DeletionDate` from `DescribeKey`, **not** the event's human-formatted `deletionDate` string |
| "Was it used" pivot | `kms:GetKeyLastUsage` — an empty `KeyLastUsage` is **not** proof of non-use; compare `KeyCreationDate` with `TrackingStartDate`. Corroborate with CloudTrail `GenerateDataKey`/`Decrypt` keyed on `resources[].ARN`, which AWS names as the authoritative source. Only successful cryptographic operations are tracked, with up to an hour of delay |
| Blast radius | Every ciphertext ever produced under the key, in every service — S3 objects, EBS volumes and snapshots, RDS instances, Secrets Manager secrets, DynamoDB tables, Backup vaults — plus every alias and grant, deleted with the key. Recreating the key with identical key material does **not** recover a symmetric key's ciphertexts: AWS binds per-key metadata into every ciphertext specifically to prevent it |
| Error strings | `ScheduleKeyDeletion` / `CancelKeyDeletion`: `KMSInvalidStateException`, `NotFoundException`, `InvalidArnException`, `DependencyTimeoutException`, `KMSInternalException`, plus `AccessDenied` / `AccessDeniedException` (match both, A7). State rejections read `<key ARN> is pending deletion` and, for a cancel on the wrong key, `<key ARN> is not pending deletion (or pending replica deletion).` Consumer side: **either** `DisabledException: <key ARN> is pending deletion (or pending replica deletion).` **or** `KMSInvalidStateException: <key ARN> is pending deletion` — match both forms |
| Key policy size | 32,768 characters, the documented maximum for `PutKeyPolicy`'s `Policy` and `CreateKey`'s `Policy`, and far below CloudTrail's 100 KB `requestParameters` omission threshold. There is therefore **no size-based evasion path and no oversized-document companion rule** in this playbook. An oversized policy throws `LimitExceededException` and is never stored |
| Recovery ordering | One-way. `CancelKeyDeletion` succeeds only in `PendingDeletion` and leaves the key **`Disabled`**; `EnableKey` fails in `PendingDeletion` and must follow the cancel. `PutKeyPolicy`, `GetKeyPolicy`, `DescribeKey`, `DeleteAlias` and `ListKeys` are all permitted while the key is pending deletion — which is how the cancel path gets closed behind you |

**MITRE mapping note.** The source maps **T1486 / TA0040** — *Data Encrypted for Impact* — and
the ID is live. It is defensible as an intent label, since extortion is the usual motive, but
imprecise as a technique description: T1486 describes an adversary *encrypting* data, and here
the adversary encrypts nothing. The data was already encrypted, by you, under your own key; what
is destroyed is the ability to reverse that. **T1485 — Data Destruction** is the accurate
primary — its platform list includes IaaS and its description covers destroying infrastructure
crucial to operations in a cloud environment — and T1486 is kept as the second tag because it is
why anyone alerts on this at all. **T1490 — Inhibit System Recovery** is a real third reading wherever the key
protects snapshots or backup vaults, since the same single call destroys both the primary copy
and the restore path; it is not carried as a tag because whether it applies depends on your
estate rather than on the event.

### Residual Risk

Cancelling the deletion and re-enabling the key restores cryptographic availability and nothing
else, and there are three things it does not fix.

**The window was an outage.** Every cryptographic operation between the schedule and the enable
was refused: retries exhausted, queues dead-lettered, backups did not run, autoscaling launches
could not attach encrypted volumes, and `EnableKey` replays none of it. The failures are silent
for anything holding an already-issued data key, so the damage surfaces later — at the next
attach, restart or restore — and will not obviously trace back to this incident.

**If a key in the account did reach its deadline, nothing in this playbook recovers it.** The
data encrypted under it is unrecoverable, permanently, and AWS is explicit that recreating the
key with the same key material does not help for symmetric keys. The response at that point is
data-loss accounting, not incident response — and the only record of what was lost is the
CloudTrail usage history you collected in Query 3 before the key's own metadata was deleted with
it. For an asymmetric key it is worse still: AWS notes that holders of the downloaded public key
"can continue to use them to encrypt messages" and "do not receive any notification that the key
state is changed", and that no alarm, log or strategy inside AWS can detect that use at all.

**And the schedule was a symptom.** A principal that could schedule a key for deletion could
also rewrite its key policy, create a grant, delete its imported key material or disable the
trail that recorded any of it. Until Query 5's session reconstruction has been read in full, and
`../kms.impact.key-policy-access-removed/PLAYBOOK.md` has been worked for every key the
principal touched, the absence of those actions is an assumption rather than a finding.
