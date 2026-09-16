# IR Playbook: S3 Block Public Access Restored — the guardrail put back via `PutBucketPublicAccessBlock`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence evasion — a guardrail is returned to its expected state after being lowered, so that a review of configuration state shows nothing wrong and only the event history holds the window |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Informational as a standalone event; high when it is the closing half of a lower-act-restore sequence by one principal. Enabling a guardrail is a good thing happening, and the source rule rates it P4 as though it were a threat. |
| MITRE Tactics | Defense Evasion |
| MITRE Techniques | T1070 |
| Services in Scope | S3, CloudTrail, IAM, AWS Config |

**What the technique does:** the actor lowers Block Public Access on a bucket, does whatever the
lowered guardrail permitted, and then sets it back. The end state is correct. Every state-based
control — AWS Config, a compliance scan, a bucket-by-bucket audit — reads the current configuration
and finds nothing, because there is nothing there to find. The exposure exists only as an interval
between two events.

**Why the usual reflexes miss it.** The first is to treat a hardening event as noise and drop it,
which removes the only record of the second half. The second is to alert on it as-is, which is what
the source rule does at P4 — that routes a guardrail being applied to a human, on every
infrastructure run, and trains them to close it. The third is to reach for containment when the
correlation fires: there is nothing to contain, the configuration is already correct, and a
responder who finds nothing to do will write it off. The fourth is to shorten the correlation window
to reduce noise, which removes the deliberate case and keeps the infrastructure-rebuild case.

**Detection thesis:** ship the hardening event at informational as change accounting, and alert only
on the ordered pair. The finding is the window, not the event.

**Adjacent playbooks.** The weakening half, split by which flag and therefore by whether data is
exposed, is `../s3.exfiltration.public-access-block-removed/`. The configuration deleted rather than
weakened is `../s3.exfiltration.public-access-block-deleted/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region, retained long enough to reconstruct an interval. This
is the one prerequisite the whole playbook rests on: the current configuration is correct by the
time anyone looks, so event history is the only evidence that anything happened. A 90-day retention
makes a 30-day-old window unreconstructable, and nothing else will show it.

`PutBucketPolicy` and `PutBucketAcl` history alongside, because "was the bucket actually public
during the window" cannot be answered from Block Public Access events alone.

CloudTrail **data events** on buckets holding sensitive data — off by default, billable, and not
enablable retroactively. Without them, "was anything read during the window" is permanently
unanswerable, and the window is exactly what this playbook is about.

AWS Config is worth having for other reasons but will not help here. It records state, and the state
is fine.

**Alerting (must be pre-configured)**

- **Block Public Access lowered, the bucket's policy or ACL changed, and the guardrail restored — all by the same principal within 24h → P0**
- **Block Public Access lowered and restored by the same principal with no recorded bucket change in between → P1**

**Response Tooling**

Read access to CloudTrail history across the relevant window, and the ability to run
`lookup-events` without a change ticket. The response here is a timeline reconstruction, so the
tooling is query tooling.

An IAM principal that can call `s3api get-bucket-policy`, `get-bucket-acl` and
`get-bucket-policy-status`, to establish what the bucket's configuration looked like around the
window.

**Known IOC Baselines**

The roles that own bucket lifecycle. An infrastructure apply that rebuilds a bucket legitimately
produces both halves of the pair in order, so without this list the correlation is dominated by
deploys. These populate `known_provisioners` on the base rules — and the base rules, not the
correlation, are where the filtering belongs.

The record of which buckets are public on purpose, shared with the other `s3.*` playbooks. A
guardrail lowered on a deliberately public bucket means something different from one lowered on a
data store.

Normal deploy cadence per bucket. A lower-restore pair that matches the deployment schedule is a
deployment; one at 03:00 on a bucket nobody has touched in six months is not.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | Block Public Access lowered, `PutBucketPolicy` or `PutBucketAcl` on the same bucket, and the guardrail then restored — all by one principal within 24h | Correlation rule | T1070 |
| P1 | Block Public Access lowered and restored by the same principal, no bucket change recorded in between | Correlation rule | T1070 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | A hardening carrying fewer than four flags — the omitted flags are in an undocumented state, so the control may not actually be applied | CloudTrail | T1070 |
| P2 | Block Public Access applied by a principal that is not a recorded provisioner, with no corresponding weakening | CloudTrail | T1070 |
| P2 | Any Block Public Access application — change accounting, routed to a log and not to a human | CloudTrail | T1070 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `PutPublicAccessBlock` — the SDK operation name | CloudTrail emits `PutBucketPublicAccessBlock` and `PutAccountPublicAccessBlock`. **The rule cannot fire**, in any account, ever, and reports clean permanently | Match the CloudTrail event names, both scopes. Verified against AWS's S3 CloudTrail event list |
| A different rule in the same pack uses the correct form | Three rules in this pack cover the same operation family and use two naming conventions between them, with no consistency. Getting one right predicts nothing about the next | Each event name checked individually against AWS's list. Recorded here so a reviewer does not generalise from a passing rule |
| `NOT (flag:false)` treated as "all four true" | All four flags are `Required: No`. A request carrying only `BlockPublicPolicy: true` satisfies the condition while leaving the other three in an undocumented state — AWS does not specify whether an omitted flag is cleared or preserved | A dedicated rule for the partial case at low, and a `FlagsPresent` count surfaced in the query so a responder can see it |
| Alerts on a guardrail being applied, at P4 | This is a good thing happening. Routed to a human on every infrastructure run, it trains responders to close it, and the one case that matters gets closed with the rest | Informational as change accounting. Only the ordered pair is routable |
| No pairing with the weakening | Alone, a restoration is unremarkable and a weakening is often ambiguous. Together, by one principal, they describe a window that no state-based control can see | A `temporal_ordered` correlation over 24h, grouped by principal |
| MITRE: none | The pack maps this rule to nothing at all | `T1070 — Indicator Removal` for restoring the expected state to conceal a change, with `T1530` on the weakening half |

**Recommended detection — informational accounting, plus the pair that is actually the finding.**

```yaml
# S3 Block Public Access enabled or strengthened — change accounting, and the cover-up half (T1070)
#
# A HARDENING EVENT IS NOT A DETECTION. Enabling a guardrail is a good thing happening; it belongs
# at informational. Its one security use is as the SECOND half of a pair — a principal who lowered
# the block, acted, and put it back has closed the window behind them, and the restored
# configuration is what makes a state-based review show nothing wrong.
#
# The source rule also matches `PutPublicAccessBlock`, the SDK operation name, so it cannot fire;
# and `NOT (flag:false)` is not `all four true` when every flag is `Required: No`.
# Full rationale: detections/detection_note_t1070.md.
title: S3 Block Public Access enabled or strengthened
id: b52d7f04-3a19-4e86-9c07-1d4e8b6f2a53
name: s3_pab_hardened
status: experimental
description: >-
  Base rule — change accounting and correlation component, never for direct alerting. A successful
  PutBucketPublicAccessBlock or PutAccountPublicAccessBlock in which no flag is set to false. On its
  own this is a guardrail being applied, which happens on every infrastructure run.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html
tags:
  - attack.defense-evasion
  - attack.t1070
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'PutBucketPublicAccessBlock'
      - 'PutAccountPublicAccessBlock'
  success:
    errorCode: null
  any_flag_false:
    requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets: false
  policy_false:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false
  acls_false:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls: false
  ignore_false:
    requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls: false
  condition: selection and success and not (any_flag_false or policy_false or acls_false or ignore_false)
level: informational
---
title: S3 Block Public Access lowered and then restored by the same principal
id: 9c31e6ab-84d7-4f52-b0a3-6e29d5178c4f
status: experimental
description: >-
  The same principal weakened Block Public Access and then set it back within a day. The end state
  is correct, which is the problem — a review of configuration state shows nothing wrong, and the
  window in between is only visible in the event history. This is the shape of a completed
  operation with the door closed behind it, and it is the one thing in this directory worth
  alerting on.
references:
  - https://attack.mitre.org/techniques/T1070/
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.defense-evasion
  - attack.collection
  - attack.t1070
  - attack.t1530
correlation:
  type: temporal_ordered
  rules:
    - s3_pab_weakened_any
    - s3_pab_hardened
  group-by:
    - userIdentity.arn
  timespan: 24h
falsepositives:
  - >-
    An infrastructure apply that tears a bucket's configuration down and rebuilds it in one run,
    which legitimately produces both halves in order. Allowlist the provisioning role on the base
    rules rather than shortening the timespan — a short timespan removes the attacker case and
    keeps the noisy one.
level: high
---
title: S3 Block Public Access partially applied and reported as hardened
id: 6f8a20d5-c74b-49e1-83b6-2a0d7e51cb96
name: s3_pab_partial_hardening
status: experimental
description: >-
  A PutBucketPublicAccessBlock in which every flag present is true but fewer than four flags are
  present. It reads as a hardening and satisfies any rule testing "no flag is false", while leaving
  the omitted flags in an undocumented state — AWS does not specify whether a flag absent from the
  request is cleared or preserved. So the resulting configuration is not derivable from the event,
  and a control that looks applied may not be. Compliance drift rather than attack, and it ships
  low because that is what it is.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html
tags:
  - attack.defense-evasion
  - attack.t1070
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'PutBucketPublicAccessBlock'
      - 'PutAccountPublicAccessBlock'
  success:
    errorCode: null
  # Four sibling keys, each requiring one flag to be PRESENT. ANDed, they mean "the request carried
  # a complete configuration" — so `not complete` is the partial case.
  complete:
    requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets|exists: true
    requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy|exists: true
    requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls|exists: true
    requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls|exists: true
  any_flag_false:
    requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets: false
  policy_false:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false
  acls_false:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls: false
  ignore_false:
    requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls: false
  condition: selection and success and not complete and not (any_flag_false or policy_false or acls_false or ignore_false)
falsepositives:
  - >-
    A tool that deliberately manages one flag and leaves the rest to the account-level setting.
    Legitimate, and worth knowing about, because the bucket's protection is then entirely dependent
    on the account floor staying set.
level: low
---
title: S3 Block Public Access weakened
id: 3e07b4c9-1d68-42fa-95e3-8c7b04af61d2
name: s3_pab_weakened_any
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful
  PutBucketPublicAccessBlock or PutAccountPublicAccessBlock setting a flag to false. The rated
  detections for this act, split by which flag and therefore by whether data is exposed now, are in
  ../../s3.exfiltration.public-access-block-removed/.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'PutBucketPublicAccessBlock'
      - 'PutAccountPublicAccessBlock'
  success:
    errorCode: null
  restrict_off:
    requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets: false
  policy_off:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false
  acls_off:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls: false
  ignore_off:
    requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls: false
  condition: selection and success and (restrict_off or policy_off or acls_off or ignore_off)
level: informational
```

What this set structurally cannot do: it cannot tell you whether the bucket was public *during* the
window, because a lowered flag only matters if a public policy or ACL existed at the time and that
state is not in these events. And it cannot tell you whether anything was read, because object
operations are data events that are off by default and cannot be enabled retroactively.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first; it establishes the window that the rest of the playbook is about.

#### Query 1 — Reconstruct the window: when it opened, when it closed, who closed it

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in PutBucketPublicAccessBlock DeleteBucketPublicAccessBlock \
           PutAccountPublicAccessBlock DeleteAccountPublicAccessBlock; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | (.requestParameters.PublicAccessBlockConfiguration // {}) as $p
      | [$p.RestrictPublicBuckets, $p.IgnorePublicAcls, $p.BlockPublicPolicy, $p.BlockPublicAcls]
        as $flags
      | ($flags | map(select(. != null)) | length) as $present
      # A Delete removes the whole configuration and is a weakening even though it carries no
      # flags. A Put with any flag false is a weakening; a Put with none false is a restoration.
      | (if (.eventName | test("Delete")) then "WEAKEN(deleted)"
         elif ($flags | index(false)) != null then "WEAKEN"
         elif $present < 4 then "harden(PARTIAL \($present)/4)"
         else "harden" end) as $dir
      | "\(.eventTime)  \($dir)  \(.userIdentity.arn)  bucket=\(.requestParameters.bucketName // "ACCOUNT")  ip=\(.sourceIPAddress)"'
done | sort
```

Sorted by time, and read as a sequence. A `WEAKEN` followed by a `harden` from the same ARN is the
pair; the gap between their timestamps is the window, and everything else in the playbook is scoped
to it. `harden(PARTIAL n/4)` means the restoration itself was incomplete and the guardrail may not
actually be back.

#### Query 2 — Was the bucket public during the window

```bash
BUCKET="${1:?bucket name from Query 1 required}"
WINDOW_START="${2:?window start timestamp from Query 1 required}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== Policy and ACL writes on this bucket, all history available ==="
for EVT in PutBucketPolicy PutBucketAcl DeleteBucketPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$WINDOW_START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg b "$BUCKET" '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null) | select(.requestParameters.bucketName == $b)
      | "\(.eventTime)  \(.eventName)  \(.userIdentity.arn)"'
done | sort

echo
echo "=== What the bucket looks like NOW (not during the window) ==="
aws s3api get-bucket-policy-status --bucket "$BUCKET" \
  --query 'PolicyStatus.IsPublic' --output text 2>/dev/null || echo "(no bucket policy)"
```

The distinction between these two blocks is the whole point. The second answers "is it public now",
which is almost always `False` by the time anyone runs it — the guardrail was restored. The first is
what tells you whether a public configuration existed while the guardrail was down, and if no policy
write appears in the window, a pre-existing public policy that the lowered flag un-suppressed is
still possible and needs the policy's own history to rule out.

#### Query 3 — Was anything read during the window

```bash
BUCKET="${1:?bucket name required}"
REGION="${AWS_REGION:-us-east-1}"

aws cloudtrail list-trails --region "$REGION" --query 'Trails[].TrailARN' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    aws cloudtrail get-event-selectors --trail-name "$T" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg t "$T" 'if (tostring | test("AWS::S3::Object"))
                          then "[OK] \($t) records S3 object data events" else empty end'
  done
echo "[!] If nothing printed [OK], reads during the window were NEVER recorded. Data events are off"
echo "    by default, billable and not enablable retroactively — absence is not a negative result."
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

This is the query that separates a deploy from an operation. A provisioning role emitting the pair
alongside twenty other resource calls in ninety seconds is a rebuild. A principal whose only
activity that day is lower, act, restore is not, and the shape is usually obvious at a glance.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**There is usually nothing to contain, and that is the most important thing to say up front.** By
the time this correlation fires the guardrail is back and the configuration is correct. A responder
who reaches for the containment reflex will find nothing to do and is likely to write the alert off.
The work here is timeline reconstruction and principal containment, in that order.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows the restoration was **partial** — `harden(PARTIAL n/4)` — the
guardrail is not actually back, and this is not the analytic case. Treat it as an open exposure, go
to `../s3.exfiltration.public-access-block-removed/` Step 1, and set all four flags explicitly
before doing anything else.

#### Step 1 — Confirm the guardrail is genuinely restored

```bash
BUCKET="${1:?bucket name required}"
ACCT="$(aws sts get-caller-identity --query Account --output text)"

aws s3api get-public-access-block --bucket "$BUCKET" \
  --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null \
| jq -r 'to_entries | map(select(.value != true) | .key) as $off
         | if ($off | length) == 0 then "[OK] all four set on the bucket"
           else "[FAIL] not set: \($off | join(","))" end'

aws s3control get-public-access-block --account-id "$ACCT" \
  --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null \
| jq -r 'to_entries | map(select(.value != true) | .key) as $off
         | if ($off | length) == 0 then "[OK] all four set at account level"
           else "[FAIL] account floor not set: \($off | join(","))" end' \
  || echo "[FAIL] no account-level block at all"
```

The event said a hardening happened; this says what the configuration actually is. They can differ,
because a request carrying fewer than four flags leaves the omitted ones in a state AWS does not
document, and only this call resolves it.

#### Step 2 — Fix the window's boundaries before the history ages out

```bash
BUCKET="${1:?bucket name required}"
OUT="./evidence-${BUCKET}"
mkdir -p "$OUT"

# CloudTrail lookup-events serves 90 days. Anything older needs the trail's S3 objects, and those
# have their own lifecycle policy. Capture now rather than when the report is being written.
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-90d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%SZ')"
for EVT in PutBucketPublicAccessBlock DeleteBucketPublicAccessBlock PutBucketPolicy \
           PutBucketAcl DeleteBucketPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
    > "${OUT}/${EVT}.json"
done
echo "[OK] event history captured under ${OUT}/"
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

The assumed-role branch prints rather than applies: an inline deny on a shared automation role can
halt a deployment pipeline, and whether that is acceptable is not a call the script can make. That
caution carries more weight here than in most playbooks, because the single most likely explanation
for this alert is a provisioning role doing its job.

#### Step 4 — Decide whether this is an incident at all

Work the pair against the §1 baselines before escalating:

- Is the principal a recorded provisioner? If yes, and the timing matches the deploy cadence, this
  is a rebuild and the correct outcome is to add the role to `known_provisioners`.
- Did a policy or ACL write land inside the window? If yes, escalate — that is the P0 shape.
- Was the bucket already carrying a public policy before the window opened? If yes, the lowered flag
  un-suppressed it and no write was needed. Query 2's history is how you find out.
- Was the restoration partial? If yes, the guardrail is not back and this is an open exposure.

---

## 4. Eradication

### Remove Attacker Access

#### Size the window honestly

The interval between the weakening and the restoration is the exposure. If a public policy existed
during it — written inside the window, or pre-existing and merely un-suppressed — treat every object
the grant covered as potentially retrieved, because unless data events were already enabled there is
no record either way. Query 3 establishes which case you are in, and "no evidence of access" is not
an available conclusion when no evidence could have existed.

#### Remove the underlying grant, not just the guardrail

If Query 2 found a public policy statement or a public ACL grant, restoring Block Public Access
suppressed its effect but did not remove it. It is still in the bucket, one flag away from being
effective again, and it will survive every audit that reads only the guardrail. Remove it — the
procedure is `../s3.exfiltration.public-access-block-removed/` Step 3.

#### Deny the lowering, so the pair cannot form

The correlation detects the sequence after the fact. Denying the first half prevents it:

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyLoweringTheAccountFloor",
  "Effect": "Deny",
  "Action": ["s3:PutAccountPublicAccessBlock", "s3:DeleteAccountPublicAccessBlock"],
  "Resource": "*",
  "Condition": {"ArnNotLike": {"aws:PrincipalARN": "arn:aws:iam::*:role/YourBreakGlassRole"}}
}
```

Attach it to an OU, not the management account, where SCPs do not apply. `YourBreakGlassRole` must
be a role that genuinely exists — an `ArnNotLike` against a non-existent role denies the action to
everyone including you. Test in a non-production OU first.

#### Keep the event history long enough to see the next one

This is the eradication step that generalises. A window this playbook can reconstruct is one whose
events are still in CloudTrail; a 90-day `lookup-events` horizon means a pair that spans a quarter
is invisible regardless of how good the rules are. Retention is the control, not the detection.

---

## 5. Recovery

### Restore Clean State

#### Verify the guardrail is complete, at both scopes

Re-run **§3 Step 1**. Recovery is verified when all four flags read `true` at the bucket and at the
account, from `get-public-access-block` rather than from the event that claimed to set them.

#### Verify the underlying configuration is clean, not merely suppressed

```bash
BUCKET="${1:?bucket name required}"

aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null \
| jq -r '
    (if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
    | select(.Effect == "Allow")
    | select([(.Principal | if type == "string" then [.] else (to_entries[].value
        | if type == "array" then .[] else . end) end)] | flatten | index("*"))
    | "[FAIL] public Allow still present — Sid=\(.Sid // "-")"'

aws s3api get-bucket-acl --bucket "$BUCKET" --output json 2>/dev/null \
| jq -r '.Grants[] | select(.Grantee.URI // "" | test("AllUsers|AuthenticatedUsers"))
         | "[FAIL] public ACL grant still present — \(.Permission)"'

echo "[OK] if nothing printed above, no public grant remains"
```

A bucket whose guardrail is restored and whose policy still carries a wildcard `Allow` is one call
from being public again, and it passes every check that reads only the guardrail. This is the check
that distinguishes recovered from suppressed.

#### Confirm the corrected detection fires

```bash
BUCKET="${1:?disposable test bucket required — do NOT use a production bucket}"
PAB_ON="BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Exercise the PROSPECTIVE flag only, so nothing can be exposed even momentarily, then restore.
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=true \
  && echo "[OK] lowered"
sleep 60
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration "$PAB_ON" \
  && echo "[OK] restored — expect the correlation, not two separate alerts, within 15 min"
```

The thing being tested is that two informational events produce one high-severity correlation. If
you receive two informational events and no correlation, the pairing is not deployed and the
directory's only routable output is missing.

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| How long was the guardrail down? | The window is the finding. Everything else in the report is scoped to it. |
| Was the principal a recorded provisioner? | The single most likely explanation for this alert is a rebuild, and confirming that is faster than any other line of enquiry. |
| Did a policy or ACL write land inside the window? | Distinguishes the P0 shape from the P1 one. |
| Was a public policy already attached before the window opened? | If so, no write was needed — the lowered flag un-suppressed what was already there, and looking only for writes inside the window misses it. |
| Was the restoration complete, or fewer than four flags? | A partial restoration means the guardrail is not back and this was never the analytic case. |
| Would any state-based control have caught this? | No, by construction — and that is the argument for the event-history retention this playbook depends on. |

### Recommended Guardrails

**Ship hardening events at informational and route them to a log, not a human.** They are change
accounting. Their value is being available for correlation, and routing them anywhere else guarantees
they get suppressed within a month, taking the correlation's second half with them.

**Keep CloudTrail history longer than your longest plausible window.** This is the only control that
makes the pair reconstructable. A configuration-state control cannot see this case at all — the
state is correct — so retention is doing the work that a compliance scan cannot.

**Deny the weakening rather than detecting the pair**, using the SCP fragment in §4. The correlation
is a good detection of something that should not have been possible.

**Populate `known_provisioners` from the first week's output.** Deployed empty, the base rules make
the correlation fire on every infrastructure run, and the fastest route to this playbook being
ignored is a correlation that is right about the sequence and wrong about the meaning every time.

**Do not shorten the 24-hour timespan to reduce noise.** It removes the deliberate case, which is
patient, and keeps the rebuild case, which is fast. Filter on the principal instead.

### Technique Reference

**T1070 — Indicator Removal.** Verified live at https://attack.mitre.org/techniques/T1070/ on
2026-08-30. Restoring a configuration to its expected value in order to conceal that it changed is
indicator removal in the cloud-control-plane sense: the artifact being removed is the *difference*,
and removing it is what makes a state-based review show nothing.

**T1530 — Data from Cloud Storage** applies to the weakening half of the pair and is tagged on the
correlation for that reason. Verified live 2026-08-30.

The source rule carried **no** MITRE mapping.

AWS references relied on throughout, all verified 2026-08-30:

- `PutPublicAccessBlock` API reference — per-flag semantics and the `Required: No` status of all
  four flags: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html
- S3 CloudTrail event names, including the API-versus-event divergence that makes the source rule
  inert: https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html

Service-wide verified behaviour shared by every `s3.*` playbook is in `../_ground-truth/s3.md`.

### Residual Risk

**Two principals defeat the correlation.** It groups by `userIdentity.arn`, so a weakening by one
identity and a restoration by another produces two informational events and no pair. Grouping by
bucket instead would catch that but would pair unrelated deploys constantly; neither grouping is
right in every case, and this one is chosen because a single actor is the common shape.

**A window longer than the timespan is invisible.** Lower on Monday, restore on Friday, and the
24-hour correlation never fires. Lengthening it trades directly against volume, and there is no
setting that catches a patient actor without pairing every unrelated deploy in the window.

**The event history is the only evidence, and it expires.** `lookup-events` serves 90 days. Beyond
that the trail's S3 objects are the source, subject to their own lifecycle policy, and once they are
gone the window is unreconstructable — not merely hard to reconstruct.

**A pre-existing public policy needs no write inside the window.** If a public statement was already
attached and merely suppressed by `RestrictPublicBuckets`, lowering that flag exposes the bucket
with no `PutBucketPolicy` to find. A responder looking only for writes inside the window will
conclude nothing happened.
