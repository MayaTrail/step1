# IR Playbook: KMS Key Disabled — cryptographic denial of service via `kms:DisableKey`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Availability impact (a customer managed KMS key is moved to the `Disabled` state, so every cryptographic operation against it is refused and every AWS resource that must ask KMS to unwrap a data key stops working) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** One API call with no confirmation step takes every workload that depends on the key offline, and AWS documents the effect as almost immediate. It is not P0-on-its-own only because it is completely reversible: `EnableKey` restores the key with nothing lost and no re-encryption. The source rule rates the single event **P4** — the lowest priority in the set — which is wrong by any reading: P4 means triage when convenient, and this is either an active outage or an actor proving it can cause one. The merged volume variant is rated P0 here against the source's P3. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1489 (the source maps T1486 — see the mapping note in `detections/detection_note_t1489.md`) |
| Services in Scope | KMS, CloudTrail, IAM, Organizations (SCP), and every service holding a resource encrypted under the key — EBS, S3, RDS, Secrets Manager, DynamoDB, EFS |

**What the technique does:** the actor calls `kms:DisableKey` with a single `KeyId` parameter — a bare key
ID, a key ARN or an alias, whichever it holds. KMS moves the key to the `Disabled` state and
returns HTTP 200 with an empty body. From that moment `Decrypt`, `Encrypt`, `GenerateDataKey`
and every other cryptographic operation on that key fails with
`DisabledException: <key ARN> is disabled.` The actor gains no credential, reads no data and
destroys nothing — the entire effect is denial of use, which is why this is the reversible half
of key-based destruction and why the actor's usual next call is `ScheduleKeyDeletion`, the half
that is not reversible.

**Detection thesis.** The discriminator is **who called and how many keys they touched** —
there is no field on the event that separates a malicious disable from a legitimate retirement,
because the two are byte-identical API calls, so the rule must carry an allowlist of the
principals that legitimately retire keys and a volume correlation for the estate walk. The
source rules capture neither: they match `eventName:"disablekey"` in lower case, which is not
the form CloudTrail writes, and even if the case were fixed they check nothing beyond the event
name.

---

## 1. Preparation

**Logging & Visibility**

- **CloudTrail management events**, on by default, `eventSource: kms.amazonaws.com`. AWS logs
  **all** KMS operations, including read-only ones and cryptographic operations — `Decrypt` and
  `GenerateDataKey` carry `"managementEvent": true` and `"eventCategory": "Management"` in
  AWS's own published examples, so `lookup-events` can answer "was this key in use", unlike a
  genuine data-plane API.
- **The per-trail KMS exclusion.** `PutEventSelectors` with `ExcludeManagementEventSources` set
  to `kms.amazonaws.com` drops **every** KMS event from that trail; it cannot be applied
  selectively and the events lost while it is in force cannot be recovered. Confirm your own
  trail with `aws cloudtrail get-event-selectors` before reading any empty KMS result as quiet.
- **Field shapes.** `requestParameters.keyId` is **caller-typed** — bare ID, ARN or alias.
  `responseElements.keyId` carries the normalised **key ARN**, flat, added by AWS in December
  2022 to `DisableKey` and `EnableKey` entries even though neither API returns a value.
  `resources[].ARN` carries the key ARN with `resources[].type` of `AWS::KMS::Key` and is the
  most reliable identity on any KMS event.
- **No `keyManager` on the event.** Whether a key is customer managed is a `DescribeKey`
  response field (`KeyMetadata.KeyManager`, `CUSTOMER` or `AWS`), not an event field. It does
  not need filtering: AWS managed keys cannot be disabled by you at all.
- **Known IOC baseline to hold ready:** the ARNs that legitimately disable keys — the key
  administration role and the IaC deployment role. This is the allowlist in the shipped rule
  and the rule is untuned without it.

**Alerting (must be pre-configured)**

- **Three or more distinct KMS keys disabled by one principal inside ten minutes → P0**
- **`DisableKey` succeeding on a key by a principal outside the key-administration allowlist → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Three or more distinct KMS keys disabled by one principal inside ten minutes | CloudTrail (management) | T1489 |
| P1 | `DisableKey` succeeding on a key by a principal outside the key-administration allowlist | CloudTrail (management) | T1489 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DisabledException` appearing on any KMS operation — a workload has hit the disabled key | CloudTrail (management) | T1489 |
| P2 | `DisableKey` refused with `AccessDenied` — the caller decided to disable a key and the policy held | CloudTrail (management) | T1489 |
| P3 | `DisableKey` followed by `ScheduleKeyDeletion` on the same key by the same principal | CloudTrail (management) | T1485 |

### Detection Rule Quality Notes

Two source rules, the same query at two thresholds, and the query cannot match the event.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `eventName:"disablekey"` in lower case | Returns nothing, ever, on a case-sensitive field match — CloudTrail writes `DisableKey`. The source set is internally inconsistent about this: its `PutKeyPolicy` rule is cased correctly while three others are not, so this is a defect and not a platform convention | `eventName: 'DisableKey'` |
| No success filter | A principal denied on twenty keys fires the identical volume alert as one that disabled twenty. The eradication work-list and the detection's own count diverge | `success:` block with `errorCode: null`, and a separate `low` rule that keeps the denials as evidence |
| No principal check | Every scheduled key retirement fires it, so the rule is muted inside a week and the real disable arrives to a muted channel | `key_administrators` allowlist block, `condition: ... and not key_administrators` |
| Single-event rule rated P4 | Lowest priority in the set for an event that is already an outage. Triage-when-convenient against an actor whose next call is `ScheduleKeyDeletion` | P1, and P0 for the volume variant |
| Volume threshold of 5 in 10 minutes, direction unstated | Waiting for the fourth and fifth key buys nothing while the outage widens, and an unstated direction means a sweep touching exactly five may fall through | `gte: 3` in a `value_count` correlation, with the tuning basis stated in the rule |
| Mapped to T1486 / *Data Encrypted for Impact* | Sends the responder hunting for ransomware artefacts and attacker-encrypted data that do not exist — nothing is encrypted here | T1489 *Service Stop* primary, T1486 retained as the second reading |

**Recommended detection — a customer managed KMS key disabled by a principal outside the key-administration allowlist.**

```yaml
# KMS Key Disabled (T1489 / T1486)
#
# DISABLING A KEY IS THE REVERSIBLE HALF OF KEY-BASED DESTRUCTION, AND THAT IS THE WHOLE
# REASON IT IS A SEPARATE USE CASE FROM SCHEDULED DELETION. `DisableKey` moves the key to
# `Disabled`; AWS documents the effect as "almost immediate (subject to eventual
# consistency)" and every cryptographic operation then fails with
# `DisabledException: <key ARN> is disabled.` Nothing is destroyed, `EnableKey` puts it back,
# and there is no clock. The sibling `../../kms.impact.kms-key-scheduled-deletion/` has a
# deadline after which no response exists at all, which is why the two responses are not the
# same and the two playbooks are not merged.
#
# WHAT DOES NOT BREAK IMMEDIATELY IS THE TRAP. AWS: the effect on DATA KEYS already issued
# under the KMS key "is delayed until the KMS key is used again". An encrypted EBS volume
# already attached to a running instance keeps serving disk I/O from the data key held in the
# Nitro hardware; the failure appears on the next attach. So "nothing has broken" is never
# evidence that nothing was affected, and the blast radius is not knowable from the event.
#
# EVERY DisableKey EVENT IN YOUR TRAIL CONCERNS A CUSTOMER MANAGED KEY. AWS managed keys
# cannot be managed by you at all — "you cannot change any properties of AWS managed keys,
# rotate them, change their key policies, or schedule them for deletion" — and AWS owned keys
# are not in your account. There is therefore no AWS-managed-key noise to filter out, and no
# `keyManager` field in the event to filter on either.
#
# THE SOURCE RULES match `eventName:"disablekey"` in lower case with no success filter, no
# principal check and no content inspection, at P4 for the single event and P3 for five in ten
# minutes. CloudTrail writes `DisableKey`; the source set is internally inconsistent about
# this — its `PutKeyPolicy` rule is cased correctly while its `disablekey`, `createkey` and
# `schedulekeydeletion` rules are not — so the lower-case form is a defect in these rules and
# not a platform convention. Both are corrected here, and the volume variant is merged into
# this file as a correlation under `07-TIERS.md` merge test 1.
title: KMS key disabled outside the key-administration allowlist
id: 2f15e404-fd9a-42bf-bf89-34c0250d54fd
name: kms_key_disabled
status: experimental
description: >-
  A customer managed KMS key was moved to the Disabled state by a principal outside the
  allowlisted key-administration set. Every cryptographic operation against the key now fails
  with DisabledException, and resources holding data keys already issued under it fail on
  their next use rather than immediately.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/kms/latest/developerguide/unusable-kms-keys.html  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1489/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1489
  - attack.t1486
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'kms.amazonaws.com'
    eventName: 'DisableKey'
  success:
    errorCode: null
  # POPULATE before deploying. Left empty this rule fires on every disable in the account,
  # which for a service where key retirement is a deliberate, scheduled act is the correct
  # default — but it is a default, not a tuned rule. List the ARNs that legitimately retire
  # keys: the key-administration role and the IaC deployment role, nothing else.
  key_administrators:
    userIdentity.arn|contains:
      - ':role/KeyAdministrator'      # replace, or delete this block entirely
      - ':role/InfrastructureDeploy'  # replace, or delete this block entirely
  condition: selection and success and not key_administrators
falsepositives:
  - >-
    A planned key retirement performed by hand outside the deployment role. Legitimate, and
    the reason the allowlist exists — allowlist the principal, never mute the rule.
  - >-
    A decommission change window that disables several keys before scheduling their deletion.
    Expected to fire, and expected to be closed against the change record.
level: high
---
# The denied attempt is evidence, and a success-only rule throws it away. A principal that
# calls DisableKey and is refused has decided to disable a key; the refusal says only that the
# key policy or IAM held. Counted separately from successes so that a principal probing twenty
# keys is never reported as a principal that disabled twenty keys (B6).
title: KMS key disable attempt denied
id: c1c7a0a0-115d-420e-9d29-2ed6bcbb4176
name: kms_key_disable_denied
status: experimental
description: >-
  A DisableKey call was refused. AccessDenied means the key policy or IAM refused the caller;
  KMSInvalidStateException means the key was already pending deletion, which is a materially
  worse finding than a denial and belongs to the scheduled-deletion playbook.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1489
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'kms.amazonaws.com'
    eventName: 'DisableKey'
  # Prefix-tolerant on purpose (A7). IAM-evaluated denials surface as `AccessDenied`,
  # service-evaluated ones as `AccessDeniedException`, and KMS's own state rejection as
  # `KMSInvalidStateException`. Confirm which forms your own trail carries.
  denied:
    errorCode|contains:
      - 'AccessDenied'
      - 'KMSInvalidStateException'
      - 'NotFoundException'
  condition: selection and denied
falsepositives:
  - >-
    An automation iterating keys it does not own — a cross-account tool or a stale key list.
    Baseline it; the same shape is what permission probing looks like.
level: low
---
# Threshold basis — derived from documented behaviour, not from an observed count. The
# technique's own baseline is ONE key: a single disable is already an outage for whatever
# depends on that key, and `kms_key_disabled` above fires high on it. This correlation
# separates one operator retiring one key from a principal walking the key estate. THREE
# distinct keys in ten minutes, not the source's five, because a decommission that touches
# three production keys inside ten minutes is already a change-window event that should be
# reconcilable against a ticket, and waiting for a fourth and fifth buys nothing while the
# outage widens. `gte`, never `gt`, so a sweep that touches exactly three does not fall
# through (F6). Baseline against your own account before deploying.
#
# The counted field is `requestParameters.keyId`, which is CALLER-TYPED — it carries whatever
# the caller passed, a bare key ID or a full key ARN. A caller alternating the two forms
# inflates the distinct count; it can never deflate it. For a volume rule that failure
# direction is safe, and it is the only key identifier present on the REQUEST side.
title: Multiple KMS keys disabled by one principal
id: 024cfba9-dd74-4ee4-9f0a-b1f90c7d9410
status: experimental
description: >-
  One principal disabled three or more distinct KMS keys inside ten minutes. That is a key
  estate being taken offline, not a key being retired.
references:
  - https://docs.aws.amazon.com/kms/latest/developerguide/enabling-keys.html  # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1489/  # retrieved 2026-08-29
tags:
  - attack.impact
  - attack.t1489
  - attack.t1486
correlation:
  type: value_count
  rules:
    - kms_key_disabled
  group-by:
    - userIdentity.arn
  timespan: 10m
  # `field` belongs INSIDE `condition` for a value_count correlation — it is the field whose
  # DISTINCT values are counted. A top-level `field:` under `correlation:` is not in the
  # specification and leaves the rule with nothing to count.
  condition:
    gte: 3
    field: requestParameters.keyId
level: high
```

The rule cannot tell you whether the key mattered. Nothing on the event names the resources
encrypted under the key, and AWS documents that data keys already issued keep working until the
key is next used — so an encrypted EBS volume already attached to a running instance produces
no error and no telemetry at all until it is next attached. Blast radius is Query 2's job, and
`kms:GetKeyLastUsage` plus the `DisabledException` fallout in `detections/kql_t1489.kql` are the
only places it can be obtained.

---

### Key Investigation Queries

> KMS is regional and key ARNs are region-scoped — run both queries per region, and remember that a multi-Region key has an independent replica in each Region with its own key state. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page**; the loop below pages on `NextToken`.

#### Query 1 — Reconstruct: who disabled which keys, when, and what was refused

```bash
REGION="<region>"; START="<ISO8601-start>"; END="<ISO8601-end>"

for EN in DisableKey EnableKey; do
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
         ip: .sourceIPAddress, agent: .userAgent, err: (.errorCode // "none"),
         msg: (.errorMessage // "-"),
         keyArn: (.responseElements.keyId
                  // ([.resources[]?.ARN] | map(select(. != null)) | first)
                  // .requestParameters.keyId // "unknown")}'
    TOKEN=$(printf '%s' "$PAGE" | jq -r '.NextToken // empty'); [ -n "$TOKEN" ] || break
  done
done
```

`keyArn` prefers `responseElements.keyId` because that is the normalised key ARN; it falls back
to `resources[].ARN` and only then to the caller-typed `requestParameters.keyId`, which is the
sole identifier present when the call **failed**. Rows with `err` of `AccessDenied` are attempts
and must be counted separately from the successes — a principal probing twenty keys is not a
principal that disabled twenty. An `EnableKey` row after a `DisableKey` row on the same
`keyArn` means the disable was already reversed; find out by whom before standing down.
`keyArn` and `caller` feed every step below.

#### Query 2 — Sweep: every disabled customer managed key in the region, and whether it was in use

```bash
REGION="<region>"

KEYS=$(aws kms list-keys --region "$REGION" --output json 2>&1)
if ! printf '%s' "$KEYS" | jq -e 'has("Keys")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — list-keys failed; nothing below is a clean result: $KEYS"
else
  for KID in $(printf '%s' "$KEYS" | jq -r '.Keys[].KeyId'); do
    META=$(aws kms describe-key --region "$REGION" --key-id "$KID" --output json 2>&1)
    if ! printf '%s' "$META" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $KID — describe-key returned no KeyState: $META"; continue
    fi
    STATE=$(printf '%s' "$META" | jq -r '.KeyMetadata.KeyState')
    MANAGER=$(printf '%s' "$META" | jq -r '.KeyMetadata.KeyManager')
    ARN=$(printf '%s' "$META" | jq -r '.KeyMetadata.Arn')
    [ "$STATE" = "Disabled" ] || continue
    [ "$MANAGER" = "CUSTOMER" ] || continue
    # Was it ever used? An EMPTY KeyLastUsage is NOT proof of non-use: AWS tracks only
    # successful cryptographic operations, only since TrackingStartDate, with up to an hour
    # of delay. A key created BEFORE tracking began and showing no usage is unknown, not idle.
    LU=$(aws kms get-key-last-usage --region "$REGION" --key-id "$KID" --output json 2>&1)
    if ! printf '%s' "$LU" | jq -e 'has("TrackingStartDate")' >/dev/null 2>&1; then
      echo "[!] $ARN  Disabled  usage=INCONCLUSIVE (get-key-last-usage failed: $LU)"; continue
    fi
    VERDICT=$(printf '%s' "$LU" | jq -r '
      if ((.KeyLastUsage.Operation // "") != "") then
        "IN-USE last=" + (.KeyLastUsage.Operation) + "@" + (.KeyLastUsage.Timestamp|tostring)
          + " trail-event=" + (.KeyLastUsage.CloudTrailEventId // "none")
      elif (.KeyCreationDate >= .TrackingStartDate) then "UNUSED-SINCE-CREATION"
      else "UNKNOWN-PREDATES-TRACKING" end')
    echo "[!] $ARN  Disabled  $VERDICT"
  done
fi
```

Every `[!]` line is a customer managed key currently unusable. `IN-USE` means the key was
serving cryptographic operations and the disable is an outage — the `trail-event` value is the
CloudTrail event ID of that last operation and is the fastest route to the consumer.
`UNKNOWN-PREDATES-TRACKING` is not a clean result and must never be counted in an all-clear:
AWS's own guidance is that CloudTrail remains the authoritative source and that last-usage
information alone is not a basis for deciding a key is idle.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="AccessDenied KMSInvalidStateException NotFoundException"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "kms.amazonaws.com") |
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
elsewhere, and whether anyone else did it too. Group by caller rather than by resource: the
question the eradication phase needs answered is *how much of this is one actor's work*, and a
per-resource list cannot say. `access_key` is emitted here because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` regardless of whether it happened — see the caveat in the preamble.

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

Keyed on the access key rather than the ARN, because one credential is used across many
sessions and the key is what identifies the credential. The per-service grouping answers the
question this playbook cannot: whether this technique was the objective or one stop on a tour.
A service in that list with no business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID — so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Containment here restores availability rather than removing access, so the order is the reverse
of most playbooks: re-enable first, contain second. Re-enabling is free, instant and loses
nothing, while every minute the key stays disabled is a minute more of failed workloads — but
check the key state before acting, because `EnableKey` **cannot** succeed on a key in
`PendingDeletion` and a failure there means you are in the sibling incident, not this one.

> Run under the **break-glass responder credentials**, not the principal under investigation.

#### Step 1 — Restore the key, after confirming which state it is actually in

```bash
REGION="<region>"; KEY_ARN="<key-arn-from-Query-1>"

META=$(aws kms describe-key --region "$REGION" --key-id "$KEY_ARN" --output json 2>&1)
if ! printf '%s' "$META" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — cannot read the key state; do not act blind: $META"
else
  STATE=$(printf '%s' "$META" | jq -r '.KeyMetadata.KeyState')
  MANAGER=$(printf '%s' "$META" | jq -r '.KeyMetadata.KeyManager')
  case "$STATE" in
    Disabled)
      if aws kms enable-key --region "$REGION" --key-id "$KEY_ARN"; then
        echo "[OK] enable-key accepted for $KEY_ARN (KeyManager=$MANAGER)"
      else
        echo "[FAIL] enable-key was rejected — read the error above before retrying"
      fi ;;
    PendingDeletion|PendingReplicaDeletion)
      echo "[FAIL] $KEY_ARN is $STATE. enable-key CANNOT succeed in this state —"
      echo "       KMS returns KMSInvalidStateException. Cancel the deletion FIRST:"
      echo "       ../kms.impact.kms-key-scheduled-deletion/PLAYBOOK.md" ;;
    Enabled)
      echo "[OK] $KEY_ARN is already Enabled — the disable was reversed before you arrived;"
      echo "     establish who called EnableKey and when from Query 1 before standing down" ;;
    *)
      echo "[!] INCONCLUSIVE — state is $STATE, which enable-key does not address" ;;
  esac
fi
```

#### Step 2 — Contain the principal

```bash
CALLER="<caller-from-Query-1>"
FREEZE='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["kms:DisableKey","kms:ScheduleKeyDeletion","kms:PutKeyPolicy","kms:DisableKeyRotation","kms:DeleteAlias","kms:DeleteImportedKeyMaterial"],"Resource":"*"}]}'

case "$CALLER" in
  *":user/"*)          # IAM user: the name is $NF. Disable keys before attaching the deny.
    UNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$UNAME" \
                 --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$UNAME" --access-key-id "$K" --status Inactive
    done
    if aws iam put-user-policy --user-name "$UNAME" --policy-name IR-KMS-Freeze \
         --policy-document "$FREEZE"; then
      echo "[OK] contained IAM user $UNAME"
    else
      echo "[FAIL] could not attach IR-KMS-Freeze to user $UNAME — contain manually"
    fi ;;
  *":assumed-role/"*)  # Role name is the 2nd '/' segment; $NF is the SESSION name.
    RNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $2}')
    if aws iam put-role-policy --role-name "$RNAME" --policy-name IR-KMS-Freeze \
         --policy-document "$FREEZE"; then
      echo "[OK] contained IAM role $RNAME"
    else
      echo "[FAIL] could not attach IR-KMS-Freeze to role $RNAME — contain manually"
    fi ;;
  *)
    echo "[!] $CALLER is root, federated or a service principal — contain manually." ;;
esac
```

The deny lists `kms:ScheduleKeyDeletion` and `kms:PutKeyPolicy` as well as `kms:DisableKey`,
because the disable is the reversible half of the technique and a contained principal that can
still schedule a deletion or rewrite a key policy has not been contained. Every action named is
a real IAM action in the `kms` namespace (E6).

---

## 4. Eradication

### Remove Attacker Access

- **Sweep every region, not just the alerting one.** Re-run Query 2 across the account's
  enabled Regions: a scripted walk disables everything `ListKeys` returns per Region, and the
  correlation fires on the third key, not the last.
- **Check for the follow-on destructive calls by the same principal.** Re-run Query 1 with
  `AttributeValue=ScheduleKeyDeletion`, then `PutKeyPolicy`, then `DisableKeyRotation`, then
  `DeleteAlias`, over the same window and the same caller. A disable that was reconnaissance
  for a deletion is a different incident, and `DeleteAlias` is how an actor makes a key hard to
  find again — aliases are the only human-readable name a key has.
- **Treat every consumer of an affected key as having failed silently.** AWS documents that
  data keys already issued keep working until the key is next used, so services that looked
  healthy through the outage window may fail at their next attach, scale-out or restore. This
  is a review of what depends on the key, not a log search — nothing records it.
- **Right-size `kms:DisableKey`.** It belongs to key administration and to nothing else; see
  the guardrail in §6. `kms:ScheduleKeyDeletion` and `kms:PutKeyPolicy` on `Resource: "*"`
  need the same review, and neither is required by any runtime workload.
- **Remove the emergency deny once the account is clean**, and assert that it is gone rather
  than assuming it:

```bash
CALLER="<caller-from-Query-1>"
case "$CALLER" in
  *":user/"*)         NAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $NF}')
                      aws iam delete-user-policy --user-name "$NAME" --policy-name IR-KMS-Freeze
                      LEFT=$(aws iam list-user-policies --user-name "$NAME" --output json 2>&1) ;;
  *":assumed-role/"*) NAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $2}')
                      aws iam delete-role-policy --role-name "$NAME" --policy-name IR-KMS-Freeze
                      LEFT=$(aws iam list-role-policies --role-name "$NAME" --output json 2>&1) ;;
  *)                  NAME=""; LEFT="" ;;
esac
if [ -z "$NAME" ]; then
  echo "[!] INCONCLUSIVE — $CALLER is not an IAM user or assumed role; check by hand"
elif ! printf '%s' "$LEFT" | jq -e 'has("PolicyNames")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — could not re-list inline policies for $NAME: $LEFT"
elif printf '%s' "$LEFT" | jq -e '.PolicyNames | index("IR-KMS-Freeze")' >/dev/null 2>&1; then
  echo "[FAIL] IR-KMS-Freeze is still attached to $NAME"
else
  echo "[OK] IR-KMS-Freeze removed from $NAME"
fi
```

---

## 5. Recovery

### Restore Clean State

#### Verify the key is Enabled — not merely "not disabled"

```bash
REGION="<region>"; KEY_ARN="<key-arn-from-Query-1>"

# The signal survives the remediation: DescribeKey is permitted in EVERY key state, including
# PendingDeletion, so this check can still return a failing value after enable-key ran.
# [FAIL] is reachable, not zero by construction.
META=$(aws kms describe-key --region "$REGION" --key-id "$KEY_ARN" --output json 2>&1)
if ! printf '%s' "$META" | jq -e '.KeyMetadata.KeyState' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — describe-key returned no KeyState; the key is NOT certified: $META"
else
  STATE=$(printf '%s' "$META" | jq -r '.KeyMetadata.KeyState')
  ENABLED=$(printf '%s' "$META" | jq -r '.KeyMetadata.Enabled')
  case "$STATE" in
    Enabled)
      if [ "$ENABLED" = "true" ]; then
        echo "[OK] $KEY_ARN KeyState=Enabled Enabled=true — usable"
      else
        echo "[!] INCONCLUSIVE — KeyState=Enabled but Enabled=$ENABLED; re-read before closing"
      fi ;;
    Disabled)
      echo "[FAIL] $KEY_ARN is Disabled. Not recovered — enable-key did not take effect" ;;
    PendingDeletion|PendingReplicaDeletion)
      echo "[FAIL] $KEY_ARN is $STATE. This is worse than where you started: the key is on a"
      echo "       deletion clock. Go to ../kms.impact.kms-key-scheduled-deletion/PLAYBOOK.md" ;;
    *)
      echo "[!] INCONCLUSIVE — KeyState=$STATE is neither recovered nor a known failure" ;;
  esac
fi
```

Three states, three verdicts, and the reason the `case` is written out rather than tested as
"not `PendingDeletion`": a key that has been cancelled out of deletion returns to **`Disabled`**,
not `Enabled`. A check that treats anything other than `PendingDeletion` as clean certifies a
disabled key as recovered — which is the exact condition this playbook exists to fix.

#### Confirm the corrected detection fires

```bash
echo 'MUST fire on:     eventSource=kms.amazonaws.com, eventName=DisableKey, no errorCode,'
echo '                  userIdentity.arn NOT matching the key_administrators allowlist'
echo 'MUST NOT fire on: the same event from arn:aws:iam::<acct>:role/KeyAdministrator'
echo 'MUST NOT fire on: eventName=DisableKey carrying errorCode=AccessDenied — that is the'
echo '                  separate low-level kms_key_disable_denied rule, by design'
echo 'MUST NOT fire on: eventName=DisableKeyRotation — a different API, a different meaning,'
echo '                  and a substring match on "DisableKey" would wrongly catch it'
echo 'CORRELATION fires on: three DISTINCT requestParameters.keyId values from one'
echo '                  userIdentity.arn inside ten minutes; two keys must NOT fire it'
echo 'EXPECTED FP, by design: a decommission change window that retires three or more keys.'
echo '                  It is meant to fire and be closed against the change record.'
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A single API call with no confirmation step took a production key offline | `kms:DisableKey` was reachable on `Resource: "*"` by a principal that is not a key administrator; no condition key constrained it |
| The outage was discovered from KMS telemetry rather than from the affected workloads | No alert on `DisabledException`, which is the error every consumer receives and the only signal that names the workloads actually affected |
| The blast radius could not be read from the event | Nothing in a `DisableKey` event names what is encrypted under the key. Data keys already issued keep working until next use, so the absence of failures during the window proves nothing |
| The alert that did fire was rated P4 | Priority was set from the reversibility of the act rather than from its immediate operational effect, so the first destructive KMS call in the account arrived at the bottom of a queue |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Key policy statement (a KMS key policy is a complete document — this is one statement of it;
// a KMS key policy, unlike other resource policies, grants NOTHING implicitly, so this Deny
// sits alongside the "Enable IAM User Permissions" account-principal statement, never instead
// of it). The same statement is valid in an SCP, and an SCP IS reachable for this technique
// because the actor is a principal inside your own organisation — unlike an externally
// initiated resource-policy abuse, where only an RCP applies.
//
// FAILURE DIRECTION, and it fails OPEN: kms:TrailingDaysWithoutKeyUsage is derived from the
// same last-usage tracking as GetKeyLastUsage, so for a key with no recorded cryptographic
// use the condition key is not in the request context, a plain NumericLessThan does not
// match, and the Deny DOES NOT APPLY. That is deliberate — retiring a never-used key is the
// case you want to allow — but it means this control protects busy keys only. Do NOT switch
// to NumericLessThanIfExists to "harden" it: that inverts the intent and blocks the
// legitimate retirement of unused keys.
{ "Sid": "DenyDisableOrDeleteOfRecentlyUsedKeys", "Effect": "Deny",
  "Principal": "*",
  "Action": ["kms:DisableKey", "kms:ScheduleKeyDeletion"],
  "Resource": "*",
  "Condition": { "NumericLessThan": { "kms:TrailingDaysWithoutKeyUsage": "90" } } }
```

- Grant `kms:DisableKey`, `kms:ScheduleKeyDeletion`, `kms:PutKeyPolicy` and
  `kms:DisableKeyRotation` to the key-administration role and nothing else — AWS's own default
  key policy separates key **administrators** from key **users** for exactly this reason, and
  no runtime workload needs any of the four. Populate the allowlist in `detections/sigma_t1489.yml`
  from that same role set so the rule and the permission agree.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1489 — Service Stop (Impact). Second reading T1486 — Data Encrypted for Impact, which is the source's mapping and describes the consequence rather than the act |
| MITRE tactic | Impact (TA0040) |
| Primary API | `kms:DisableKey`. Reversed by `kms:EnableKey`. Escalated by `kms:ScheduleKeyDeletion` |
| Event source | `kms.amazonaws.com`, **management** plane, on by default — verified against AWS's published `DisableKey` CloudTrail example. Every KMS operation including `Decrypt` and `GenerateDataKey` is a management event, so `lookup-events` sees them all |
| Key discriminator | The calling principal, against the set that legitimately retires keys — there is no field on the event that distinguishes malicious from routine, because the API calls are identical |
| Ground-truth signal | `responseElements.keyId` (normalised key ARN) and `resources[].ARN`; `requestParameters.keyId` is caller-typed and is the only identifier on a failed call |
| "Was it used" pivot | `kms:GetKeyLastUsage` — but an empty `KeyLastUsage` is **not** proof of non-use; compare `KeyCreationDate` with `TrackingStartDate`, and fall back to CloudTrail `Decrypt`/`GenerateDataKey`, which AWS names as the authoritative source |
| Blast radius | Every resource whose data key must be unwrapped by this key — EBS volumes on next attach, S3 objects on next read, RDS on next start, Secrets Manager on next retrieval. Data keys already in memory keep working until next use, so the radius is larger than the errors show |
| Error strings | Caller side: `AccessDenied` / `AccessDeniedException`, `KMSInvalidStateException`, `NotFoundException`, `InvalidArnException`, `DependencyTimeoutException`, `KMSInternalException`. Consumer side: `DisabledException: <key ARN> is disabled.` — and for a key already pending deletion, **either** `DisabledException: <key ARN> is pending deletion (or pending replica deletion).` **or** `KMSInvalidStateException: <key ARN> is pending deletion`. Match both forms |
| Reversibility | Complete. `EnableKey` restores the key with no data loss and no re-encryption — but `EnableKey` fails with `KMSInvalidStateException` while the key is in `PendingDeletion`, so the cancel must come first |
| Merge record | The volume variant is merged into this playbook under `07-TIERS.md` merge test 1 — see `_source/PROVENANCE.md` |

### Residual Risk

Re-enabling the key restores cryptographic availability and nothing else. Every operation
refused during the window has already failed: retries that exhausted, queue consumers that
dead-lettered, autoscaling launches that could not attach a volume, backups that did not run.
None of that is replayed by `EnableKey` and none of it is recorded as attributable to the key,
so the operational recovery is a separate workstream from this playbook. If the actor read data
before disabling the key, the disable tells you nothing about it — `Decrypt` calls are in the
trail but their plaintext is not, and KMS never records what was decrypted. And a principal that
could disable a key could also schedule its deletion or rewrite its key policy: until Query 1
has been re-run for `ScheduleKeyDeletion` and `PutKeyPolicy` over the same window, the absence
of those events is an assumption, not a finding.
