# IR Playbook: KMS Keys Scheduled for Deletion — the decryption path removed via `kms:ScheduleKeyDeletion`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Impact / data destruction (the key that decrypts data is scheduled for destruction, making every ciphertext under it permanently unreadable when the window expires) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High for a single key, Critical for several or for a window with under 48 hours left. The outcome is irreversible and total — after expiry there is no support path and no backup of key material — but it is preceded by a mandatory 7-to-30-day waiting period, which makes this one of the few destructive AWS actions that is fully recoverable while it is running. The source rule requires five keys in ten minutes before it says anything. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485 |
| Services in Scope | KMS, S3, EBS, RDS, Secrets Manager, and every service holding data encrypted under the key |

**What the technique does:** the actor calls `kms:ScheduleKeyDeletion` on a customer-managed key.
AWS moves the key to `PendingDeletion` and enforces a waiting period — 7 to 30 days, caller's
choice, defaulting to 30. During the window the key cannot be used, so decrypt calls already fail;
at the end of it AWS destroys the key material. Every object encrypted under that key becomes
permanently unreadable, including backups and snapshots, because they hold ciphertext rather than
plaintext.

**Why the usual reflexes miss it.** The reflex is to look for deleted data, and none is deleted —
the S3 objects, the EBS volumes and the RDS storage are all exactly where they were. What has gone
is the ability to read them, and nothing in those services reports it until something tries to
decrypt. The second reflex is a volume threshold, which is what the source rule uses: five keys in
ten minutes describes a script and misses one key deliberately chosen. And the third is to assume
destruction is irreversible and therefore that investigation comes first — here it is the opposite,
because the waiting period is a real undo window and cancelling is free.

**Detection thesis:** one scheduled deletion by a principal that does not own key lifecycle is the
alert. Volume is an escalation, not an entry condition, and the triage metric is **hours remaining**
rather than count.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `kms.amazonaws.com`.** `ScheduleKeyDeletion`,
  `CancelKeyDeletion`, `DisableKey`, `PutKeyPolicy` and `DisableKeyRotation` are management events
  and on by default. `responseElements.deletionDate` carries the expiry — the field the whole
  response is timed against.
- **A key-to-consumer map**, maintained. KMS records that a key exists; what it protects is in the
  consuming services — S3 bucket encryption configuration, EBS volume attributes, RDS storage
  encryption, Secrets Manager secrets — and each must be asked separately. Building this during an
  incident costs hours the window may not have.
- **CloudWatch alarms on `KMSInvalidStateException`** from the consuming services. `DisableKey` is
  immediate, so this is where the outage surfaces first and fastest.
- **A record of which keys are multi-Region primaries and where their replicas live.** A primary
  cannot be deleted while replicas exist, which changes what a schedule against one actually means.

**Alerting (must be pre-configured)**
- **`ScheduleKeyDeletion` succeeding for a principal outside the key-lifecycle allowlist → P0**
- **`ScheduleKeyDeletion` with `pendingWindowInDays` of 7 — the shortest AWS permits → P0**
- **Five or more distinct keys scheduled by one principal within ten minutes → P0**
- **More than three refused `ScheduleKeyDeletion` calls by one principal in an hour → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under
  investigation, and `jq`. The responder needs `kms:CancelKeyDeletion` and `kms:EnableKey`
  specifically — a read-only incident role cannot perform the one action that matters here.
- The key-to-consumer map from §1, and the key policy for each key in infrastructure code.

**Known IOC Baselines**
- **Which principals legitimately schedule key deletions.** This should be one automation role and
  a break-glass path, and it is the tuning surface for the whole detection.
- The set of keys that are genuinely being decommissioned, with their expected deletion dates. A
  scheduled deletion on that list is expected; one that is not is the finding.
- The expected `pendingWindowInDays` for routine decommissioning — if the organisation always uses
  30, then any other value is a deviation worth reading.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `ScheduleKeyDeletion` succeeding for a principal outside the key-lifecycle allowlist | CloudTrail (management) | T1485 |
| P0 | Five or more distinct keys scheduled for deletion by one principal within ten minutes | CloudTrail (management) | T1485 |
| P0 | `ScheduleKeyDeletion` with `pendingWindowInDays: 7` — the minimum AWS permits | CloudTrail (management) | T1485 |
| P1 | More than three refused `ScheduleKeyDeletion` calls by one principal within an hour | CloudTrail (management) | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DisableKey` on a key with active consumers — immediate effect, no waiting period, fully reversible | CloudTrail (management) | T1485 |
| P2 | `PutKeyPolicy` removing decrypt access while leaving the key enabled | CloudTrail (management) | T1485 |
| P3 | `CancelKeyDeletion` — expected during a response, and worth confirming it was your team | CloudTrail (management) | T1485 |

### Detection Rule Quality Notes

The source rule is one threshold query at five in ten minutes, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| A threshold of five keys in ten minutes | Describes a script, not the technique. One customer-managed key can be the only thing between an attacker and every object encrypted under it, and a deliberate single deletion never reaches the threshold | The single-key case ships at high with a principal allowlist; volume becomes an escalation at critical rather than the entry condition |
| Discards refused attempts | Repeated `ScheduleKeyDeletion` denials are a principal mapping which keys it can destroy. They change no state, so nothing else in the estate notices — and they are the earliest warning available | A denial base rule and a refusal correlation, both shipped |
| Ignores `pendingWindowInDays` | AWS permits 7 to 30 days and defaults to 30. Choosing 7 shortens the response window by three quarters, and routine decommissioning has no reason to. The field is in the same request | Its own P0 trigger, and the KQL surfaces the minimum window per principal |
| No coverage of `DisableKey` | Disabling is immediate, has the same practical effect while it lasts, and is fully reversible — which makes it the quieter choice. A rule watching only scheduled deletion cannot see it | Shipped as a P2 trigger, and combined with a schedule in the KQL verdict as a worse shape than either alone |
| Counts events rather than time remaining | The triage question for this technique is *how long is left to cancel*, and `responseElements.deletionDate` answers it directly. A count does not | The KQL computes hours remaining and sorts on it; the verdicts escalate on proximity to expiry rather than on volume |
| MITRE `T1486` | That technique is an adversary encrypting data to deny access. Here the data is already encrypted and the key is being removed — the inverse | `T1485 — Data Destruction` |

**Recommended detection — one key is the alert; time remaining is the triage.**

```yaml
# Multiple KMS Keys Scheduled for Deletion (T1485 / T1486)
#
# THIS IS A DIFFERENT USE CASE FROM ITS SINGULAR SIBLING, NOT A LOUDER ONE. The per-key
# playbook at ../../kms.impact.kms-key-scheduled-deletion/ carries the same observable, and
# the two are deliberately NOT merged: at volume the containment work-list cannot come from
# the alerting events. The alert fires at its threshold while the actor's set is unbounded and
# `lookup-events` pages at 50, so the first containment step is a live list-keys/describe-key
# state sweep and containment cannot begin until it completes. The step order inverts too —
# see below.
#
# THE RE-SCHEDULE RACE IS WHY THE PRINCIPAL IS SEVERED BEFORE THE CANCEL LOOP RUNS.
# `CancelKeyDeletion` returns a key to the `Disabled` state, and AWS's key-state table permits
# `ScheduleKeyDeletion` on a key that is `Disabled`. A responder cancelling in a loop against a
# still-live scheduling loop can therefore lose keys it has already saved, silently, and the
# only evidence is a second ScheduleKeyDeletion event on a key already worked. At one key that
# race is a curiosity; at fifty it is the whole incident.
#
# THE DEADLINES ARE A QUEUE, NOT A DEADLINE. Each key carries its own PendingWindowInDays
# between 7 and 30 — a caller can stagger them deliberately — so a mass event produces a spread
# of expiry dates that must be worked in ascending DeletionDate order, taken from DescribeKey
# rather than from the events, because AWS documents the real deletion as up to 24 hours later
# than the one scheduled.
#
# DENIALS ARE COUNTED SEPARATELY AND ON PURPOSE (B6). An actor iterating `ListKeys` and calling
# ScheduleKeyDeletion on everything produces a burst of AccessDenied around a handful of
# successes. A success-only rule reports the handful and hides the intended blast radius, which
# is the whole key estate.
#
# THE SOURCE RULE matches `eventName:"schedulekeydeletion"` in lower case — not the form
# CloudTrail writes — with no success filter, no group-by and a threshold of 5 in 10 minutes at
# P2. Corrected here: correct casing, a success filter, grouped by principal, and retuned to
# three distinct keys with the basis stated below.
title: Multiple KMS keys scheduled for deletion by one principal
id: 0d826da8-b146-4d1e-a8ac-2d5b5c06b4dc
status: experimental
description: >-
  One principal scheduled three or more distinct KMS keys for deletion inside ten minutes.
  That is a key estate being destroyed on a timer, not a key being decommissioned. Every key
  is already unusable and each is deleted permanently when its own waiting period expires.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
  - attack.t1486
correlation:
  type: value_count
  rules:
    - kms_key_scheduled_deletion_component
  group-by:
    - userIdentity.arn
  timespan: 10m
  # Threshold basis — derived from documented behaviour, not an observed count. The technique's
  # own baseline is ONE key, and the singular sibling already fires `high` on it, so this
  # correlation is not a detection of last resort — it is the signal that changes the RESPONSE
  # from "cancel one deletion" to "sever the principal, then sweep live state". Three distinct
  # keys inside ten minutes is the point at which no single change action explains the burst;
  # waiting for the source's five costs two more keys' worth of window for nothing. `gte`,
  # never `gt`, so a sweep touching exactly three does not fall through (F6). Baseline against
  # your own decommission runs before deploying.
  #
  # `field` belongs INSIDE `condition` for a value_count correlation — it is the field whose
  # DISTINCT values are counted. The counted field is caller-typed (a bare key ID or a key
  # ARN, whatever the caller passed), so a caller mixing the two forms inflates the count and
  # can never deflate it. For a volume rule that failure direction is safe.
  condition:
    gte: 3
    field: requestParameters.keyId
level: critical
---
# Base rule — sequence component only, not for direct alerting. The per-key event is alerted on
# in its own right, at its own priority, by
# ../../kms.impact.kms-key-scheduled-deletion/detections/sigma_t1485.yml; this copy exists
# because a Sigma correlation resolves its base rules by `name:` within the SAME file (B8).
# Kept at informational so it cannot page twice, and carrying the success filter the
# correlation needs (D-f) — without it a principal DENIED on twenty keys would fire a
# `critical` mass-destruction alert having destroyed nothing.
title: KMS key scheduled for deletion (volume component)
id: 2cdb5386-c634-4aec-a799-775b2cbf2c06
name: kms_key_scheduled_deletion_component
status: experimental
description: >-
  Base rule — volume component only, not for direct alerting. A successful ScheduleKeyDeletion,
  counted by the mass-destruction correlation above.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html  # retrieved 2026-08-29
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
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# The refusals are the shape of the sweep, and they are the reason the eradication work-list is
# bigger than the detection's success count. An actor iterating ListKeys and calling
# ScheduleKeyDeletion on everything it returns is refused on every key whose policy holds — so
# the denials enumerate the INTENDED blast radius, which a success-only rule never sees.
title: KMS key deletion attempt denied
id: 58b4072f-9b19-4d94-94d5-7150bbc7cca4
name: kms_key_deletion_denied
status: experimental
description: >-
  A ScheduleKeyDeletion call was refused. AccessDenied means the key policy or IAM held;
  KMSInvalidStateException means the key was already pending deletion or is otherwise in an
  incompatible state.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html  # retrieved 2026-08-29
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
  # Prefix-tolerant on purpose (A7): IAM-evaluated denials surface as `AccessDenied`,
  # service-evaluated ones as `AccessDeniedException`. Confirm which forms your trail carries.
  denied:
    errorCode|contains:
      - 'AccessDenied'
      - 'KMSInvalidStateException'
      - 'NotFoundException'
  condition: selection and denied
falsepositives:
  - >-
    An automation iterating a stale key list, or one that owns keys in another account.
    Baseline it — the same shape is what an estate sweep looks like.
level: low
---
# Threshold basis. Five refusals from one principal in ten minutes is not a permission problem;
# it is a loop. The count is of EVENTS rather than distinct keys because a retrying script hits
# the same key repeatedly and that repetition is itself the signal, and because the key
# identifier on a failed call is the caller-typed request parameter — the least reliable field
# on the event. Set alongside the `critical` success correlation above, this is the rule that
# fires when the key policies held and nothing was destroyed.
title: Repeated KMS key deletion attempts refused for one principal
id: cfc4e99a-3275-4fd2-9e1a-8f9878f161b9
status: experimental
description: >-
  One principal was refused five or more ScheduleKeyDeletion calls inside ten minutes. Nothing
  was destroyed; the key policies held. Treat the refused set as the intended blast radius.
references:
  - https://attack.mitre.org/techniques/T1485/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: event_count
  rules:
    - kms_key_deletion_denied
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 5
level: high
```

What this set structurally cannot do: it cannot tell you what a key protects. KMS records that a
key exists and was used, never what it encrypted — the blast radius is assembled from the consuming
services, each asked separately, and Query 3 does that. It also cannot see a decrypt failure: those
surface as `KMSInvalidStateException` in the **calling** service's logs, not in KMS.

---

### Key Investigation Queries

> KMS is regional and these are **management** events, on by default. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events
> per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: which keys, by whom, and how long is left

```bash
REGION="us-east-1"
SINCE=$(date -u -v-35d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '35 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ScheduleKeyDeletion \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     key: (.requestParameters.keyId // "-"),
     window_days: (.requestParameters.pendingWindowInDays // .responseElements.pendingWindowInDays // "-"),
     deletion_date: (.responseElements.deletionDate // "-"),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.deletion_date)'
```

The lookback is 35 days deliberately — longer than the maximum 30-day window, so a deletion
scheduled at the far end is still visible. Sort by `deletion_date`, not by event time: the key
scheduled first is not necessarily the one expiring first, and the one expiring first is where the
response starts. A `window_days` of 7 is the minimum AWS permits and is a deliberate narrowing of
your response window.

#### Query 2 — Sweep: every key currently pending deletion or disabled

```bash
REGION="us-east-1"

for K in $(aws kms list-keys --region "$REGION" --output json | jq -r '.Keys[].KeyId'); do
  aws kms describe-key --key-id "$K" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.KeyMetadata |
      select(.KeyState == "PendingDeletion" or .Enabled == false) |
      "[\(if .KeyState == "PendingDeletion" then "FAIL" else "!   " end)] \(.KeyId)  state=\(.KeyState)  deletion=\(.DeletionDate // "-")  manager=\(.KeyManager)  multiregion=\(.MultiRegion // false)  desc=\(.Description // "-")"'
done
echo "[i] KeyManager=AWS means an AWS-managed key, which cannot be scheduled for deletion by a"
echo "    customer principal — a CUSTOMER key in PendingDeletion is the actionable set."
```

This is live state and it is the authoritative answer to "what is currently at risk", including
keys scheduled before the CloudTrail retention window. `MultiRegion: true` on a primary matters: it
cannot be deleted while replicas exist, so the schedule may be blocked by AWS regardless of intent.

#### Query 3 — Inspect: what the key actually protects

```bash
REGION="us-east-1"
KEY_ARN="<key-arn-from-Query-2>"

echo "== aliases, which are usually the only human-readable clue =="
aws kms list-aliases --region "$REGION" --output json | \
  jq -r --arg k "${KEY_ARN##*/}" '.Aliases[] | select(.TargetKeyId == $k) | .AliasName'

echo
echo "== S3 buckets whose default encryption names this key =="
for B in $(aws s3api list-buckets --output json | jq -r '.Buckets[].Name'); do
  aws s3api get-bucket-encryption --bucket "$B" --output json 2>/dev/null | \
    jq -r --arg k "$KEY_ARN" '.ServerSideEncryptionConfiguration.Rules[]?
      | select(.ApplyServerSideEncryptionByDefault.KMSMasterKeyID == $k)
      | "  s3://'"$B"'"'
done

echo
echo "== EBS volumes and RDS instances encrypted with it =="
aws ec2 describe-volumes --region "$REGION" --output json | \
  jq -r --arg k "$KEY_ARN" '.Volumes[] | select(.KmsKeyId == $k) | "  ebs \(.VolumeId) (\(.Size) GiB, \(.State))"'
aws rds describe-db-instances --region "$REGION" --output json 2>/dev/null | \
  jq -r --arg k "$KEY_ARN" '.DBInstances[] | select(.KmsKeyId == $k) | "  rds \(.DBInstanceIdentifier)"'

echo
echo "== Secrets Manager secrets encrypted with it =="
aws secretsmanager list-secrets --region "$REGION" --output json 2>/dev/null | \
  jq -r --arg k "$KEY_ARN" '.SecretList[] | select(.KmsKeyId == $k) | "  secret \(.Name)"'

echo
echo "[!] This is not exhaustive. A key policy can grant use to another ACCOUNT, and data there"
echo "    will not appear in any of the above. Read the key policy before declaring the blast"
echo "    radius complete."
```

Each service is asked separately because KMS does not hold this mapping — it records that a key
was used, never what it protected. The closing caveat is load-bearing: a cross-account grant means
data outside this account depends on the key, and nothing in this account can enumerate it.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique)})'
```

Keyed on the access key rather than the ARN, since one credential spans many sessions. Key
destruction is rarely the first thing an actor does — look for what preceded it, and in particular
for data being read or copied before the key that protects it was scheduled to go.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Cancel first, investigate second.** This is the opposite of the usual order and it is correct
here: cancelling is free, fully reversible, and the window is finite. Understanding why it happened
can wait; the expiry cannot.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being investigated. The responder needs `kms:CancelKeyDeletion` and `kms:EnableKey` —
> a read-only incident role cannot perform the one action that matters.

#### Step 1 — Cancel every pending deletion, nearest expiry first

```bash
REGION="us-east-1"

for K in $(aws kms list-keys --region "$REGION" --output json | jq -r '.Keys[].KeyId'); do
  aws kms describe-key --key-id "$K" --region "$REGION" --output json 2>/dev/null | \
    jq -r 'select(.KeyMetadata.KeyState == "PendingDeletion")
           | "\(.KeyMetadata.DeletionDate)\t\(.KeyMetadata.KeyId)"'
done | sort | while IFS=$'\t' read -r WHEN KEY; do
  echo "[i] cancelling $KEY (was due $WHEN)"
  aws kms cancel-key-deletion --key-id "$KEY" --region "$REGION" --output json | \
    jq -r '"    [OK] cancelled \(.KeyId)"' \
    || echo "    [FAIL] could not cancel $KEY — check permissions and act now, not after triage"
done
```

Sorted by deletion date so the nearest expiry is handled first. Cancelling is reversible in both
directions: if a deletion turns out to have been legitimate, it can simply be rescheduled.

#### Step 2 — Re-enable, because cancelling does not

```bash
REGION="us-east-1"

for K in $(aws kms list-keys --region "$REGION" --output json | jq -r '.Keys[].KeyId'); do
  STATE=$(aws kms describe-key --key-id "$K" --region "$REGION" \
          --output text --query 'KeyMetadata.KeyState' 2>/dev/null)
  MGR=$(aws kms describe-key --key-id "$K" --region "$REGION" \
        --output text --query 'KeyMetadata.KeyManager' 2>/dev/null)
  if [ "$STATE" = "Disabled" ] && [ "$MGR" = "CUSTOMER" ]; then
    echo "[i] $K is Disabled — enabling"
    aws kms enable-key --key-id "$K" --region "$REGION" \
      && echo "    [OK] enabled $K" || echo "    [FAIL] could not enable $K"
  fi
done
```

**`CancelKeyDeletion` returns the key to `Disabled`, not to `Enabled`.** A responder who cancels
and stops has left every consumer still failing with `KMSInvalidStateException`. This step is not
optional and it is the one most easily missed.

#### Step 3 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
  for K in $(aws iam list-access-keys --user-name "$U" --output json | jq -r '.AccessKeyMetadata[].AccessKeyId'); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
  done
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

#### Step 4 — Establish what was read before the key was scheduled

Key destruction is usually the last step, not the first. Query 4's per-service breakdown for the
same credential, over the days **before** the schedule, is where the actual objective shows —
data copied while it was still readable, and then the key removed to slow the investigation.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm no key remains pending or disabled

Re-run Query 2. Every customer-managed key should be `Enabled`. A key left `Disabled` after a
cancellation is an outage nobody has noticed yet, because the failure surfaces in the consuming
service rather than in KMS.

#### Right-size who can schedule a deletion

`kms:ScheduleKeyDeletion`, `kms:DisableKey` and `kms:PutKeyPolicy` belong to a key-administration
role, not to application credentials. Query 4's principal is the starting point, and the key policy
itself is a second boundary — an IAM policy alone does not grant KMS access unless the key policy
allows it.

#### Close the key policy as well as the IAM policy

KMS is one of the few services where the resource policy is mandatory: access requires both. A key
policy that grants `kms:*` to the account root delegates the decision entirely to IAM, which is
where most over-permission in this service comes from.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or retired.

---

## 5. Recovery

### Restore Clean State

#### Verify every customer key is enabled and none is pending

```bash
REGION="us-east-1"
BAD=0
for K in $(aws kms list-keys --region "$REGION" --output json | jq -r '.Keys[].KeyId'); do
  read -r STATE MGR <<<"$(aws kms describe-key --key-id "$K" --region "$REGION" \
     --output text --query '[KeyMetadata.KeyState,KeyMetadata.KeyManager]' 2>/dev/null)"
  [ "$MGR" = "CUSTOMER" ] || continue
  [ "$STATE" = "Enabled" ] || { echo "[FAIL] $K state=$STATE"; BAD=$((BAD+1)); }
done
[ "$BAD" -eq 0 ] && echo "[OK] every customer-managed key is Enabled"
```

#### Verify the consumers actually work again

```bash
REGION="us-east-1"
KEY_ARN="<key-arn>"

CIPHER=$(aws kms encrypt --key-id "$KEY_ARN" --plaintext "$(printf 'ir-probe' | base64)" \
         --region "$REGION" --output text --query CiphertextBlob 2>/dev/null)
if [ -n "$CIPHER" ]; then
  OUT=$(aws kms decrypt --ciphertext-blob "fileb://<(echo "$CIPHER" | base64 --decode)" \
        --region "$REGION" --output text --query Plaintext 2>/dev/null || true)
  [ -n "$OUT" ] && echo "[OK] encrypt and decrypt both succeed against $KEY_ARN" \
                || echo "[FAIL] decrypt failed — the key is enabled but the key policy may still deny"
else
  echo "[FAIL] encrypt failed — key not usable; re-check state and key policy"
fi
```

A round trip is the real assertion. `Enabled` is a state; being able to decrypt is the outcome, and
a key policy change during the incident can leave the first true while the second is false.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=kms.amazonaws.com  eventName=ScheduleKeyDeletion  no errorCode"
echo "  ONE key, by an ARN outside the key-lifecycle allowlist"
echo "  (the source rule needs five in ten minutes and says nothing about this)"
echo "and MUST escalate on:"
echo "  requestParameters.pendingWindowInDays=7 — the minimum AWS permits"
echo "The rule MUST NOT fire on:"
echo "  ScheduleKeyDeletion by the key-administration role on a key listed for decommissioning"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could schedule a customer key for deletion | `kms:ScheduleKeyDeletion` reachable through both the IAM policy and the key policy for a principal that does not administer keys |
| A single key deletion produced no alert | The rule required five in ten minutes, a shape that describes a script rather than a deliberate act |
| Refused attempts went unrecorded | Denials change no state, so nothing else in the estate noticed a principal mapping which keys it could destroy |
| The blast radius took hours to establish | No key-to-consumer map existed, and KMS does not hold one |
| A cancelled key stayed unusable | `CancelKeyDeletion` returns a key to `Disabled`, and re-enabling is a separate call that was missed |

### Recommended Guardrails

**Keep key destruction in the key-administration role**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy",
             "kms:DisableKeyRotation"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/KeyAdministration"] } }
}
```

**Structural controls**
- Maintain the key-to-consumer map as a scheduled inventory. It is the artifact that turns a
  multi-hour blast-radius question into a lookup, and the response window is finite.
- Use the maximum 30-day pending window as policy, and alert on any shorter one. The window is the
  only recovery mechanism this technique has, and shortening it is the attacker's interest.
- Write the key policy to deny `kms:ScheduleKeyDeletion` to everything except the administration
  role. KMS requires both the IAM policy and the key policy to allow, so the key policy is a second
  independent boundary and it travels with the key.
- Alarm on `KMSInvalidStateException` in the consuming services. `DisableKey` is immediate, and
  that exception is the fastest signal that a key has become unusable.

**Detection improvements**
- Alert on one key, not five. A deliberate destruction targets the key that matters and never
  reaches a volume threshold.
- Read `pendingWindowInDays`. The minimum value is a deliberate narrowing of the response window
  and it is in the same request as the deletion.
- Keep the refusals. They change no state, so this is the only place they will ever be seen, and
  they precede the successful attempt.
- Triage on time remaining rather than on count. `responseElements.deletionDate` gives it directly.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1485 — Data Destruction |
| MITRE tactic | Impact (TA0040) |
| Primary API | `kms:ScheduleKeyDeletion`; `kms:DisableKey` and `kms:PutKeyPolicy` as the immediate-effect alternatives |
| Event source | kms.amazonaws.com, management plane, on by default |
| Key discriminator | The calling principal. `ScheduleKeyDeletion` carries nothing else separating decommissioning from destruction — `pendingWindowInDays` raises urgency, it does not establish intent |
| Ground-truth signal | `describe-key` — `KeyState` of `PendingDeletion` with a `DeletionDate`. Live state, and it includes keys scheduled before the trail's retention window |
| "Was it used" pivot | Not applicable — the scheduling *is* the act. The equivalent question is what the key protects, which is Query 3, and what was read before it, which is Query 4 |
| Blast radius | Every ciphertext under the key, including backups and snapshots, since those hold ciphertext. Plus anything in another account reached through a key policy grant, which this account cannot enumerate |
| Error strings | `KMSInvalidStateException` on a decrypt against a disabled or pending key — reported by the **calling** service, not by KMS. `NotFoundException`, `InvalidArnException` on the KMS calls; denials as `AccessDenied` / `AccessDeniedException`, both forms |

**MITRE mapping note:** the source carries `T1486 — Data Encrypted for Impact`, which describes an
adversary encrypting data to deny access to it. This is the inverse: the data is already encrypted
and the key that decrypts it is being removed, so `T1485 — Data Destruction` is the correct
mapping. Verified live 2026-08-30. `T1486` is defensible only in that the outcome resembles
ransomware without the ransom demand — but the mechanism, the telemetry and the response are all
different, and mapping by outcome resemblance is how a playbook ends up pointing at the wrong
procedure.

### Residual Risk

If any key's window expired before it was cancelled, every ciphertext under it is permanently
unreadable — there is no support path, no backup of key material and no recovery of any kind, and
that includes snapshots and backups because they store ciphertext rather than plaintext. Cancelling
restores the key and does not restore the period during which it was pending: decrypt calls failed
throughout, and whatever depended on them failed with them. A key policy grant to another account
means data outside this one depended on the key and cannot be enumerated from here, so the blast
radius stated in the incident is a floor. And key destruction is usually the last step of an
intrusion rather than the first — the data was readable before the key was scheduled, and what left
in that period is a separate question this playbook does not answer.
