# IR Playbook: Secrets Manager Rotation Turned Off — `CancelRotateSecret` makes a stolen value permanent

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence — automatic rotation is switched off, so a credential the actor already holds stops expiring |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when rotation is cancelled across several secrets, or after the value was read; high for a single cancellation that is not restored; medium for a refused attempt. The source rule is P3. |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1098 |
| Services in Scope | Secrets Manager, Lambda, CloudTrail |

**What the technique does:** the actor turns off automatic rotation. Nothing breaks, nothing errors,
and no telemetry is lost. The only observable change is that `LastRotatedDate` stops advancing — and
a credential the actor already holds remains the live one indefinitely.

The second is classing it as defence
evasion, when nothing about the defender's visibility changes. The third is the severity — a P3 for
the call that makes a stolen credential permanent. The fourth is the response: running
`RotateSecret` alone against a cancelled rotation produces a rotation that silently refuses to start.

**Detection thesis:** rate on scope, alert on the refused attempt the source rule excludes, and
check rotation **state** on a schedule, because that survives every way an event rule can fail.

**Adjacent playbooks.** An actor writing their own value into a secret is
`../secretsmanager.persistence.secret-value-replaced/`. Deletion is
`../secretsmanager.impact.secret-deleted/`. Enumeration is
`../secretsmanager.discovery.secrets-enumerated/` and
`../secretsmanager.discovery.access-repeatedly-denied/`. Retrieval volume is
`../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. AWS records **all** Secrets Manager API calls as
management events, so this playbook needs nothing purchased — see
`../_ground-truth/secretsmanager.md` §1.

**A recorded rotation posture per secret**: enabled or not, the schedule, and the rotation Lambda's
ARN. `CancelRotateSecret` produces no error and no outage, so without a baseline the only evidence
that rotation used to be on is the event itself.

**A scheduled check that rotation is still enabled where it should be.** This is the control that
catches the technique when the rule does not, because it tests state rather than events — and it
survives event-name casing, principal exclusions and rules that were never deployed.

**Alerting (must be pre-configured)**

- **Rotation cancelled on three or more distinct secrets by one principal in thirty minutes → P0**
- **A successful `GetSecretValue` followed by `CancelRotateSecret` on the same secret → P0**
- **`CancelRotateSecret` succeeding outside automation with no `RotateSecret` afterwards → P1**
- **`CancelRotateSecret` refused → P2**

**Response Tooling**

An IAM principal that can call `secretsmanager list-secret-version-ids`,
`secretsmanager update-secret-version-stage` and `secretsmanager rotate-secret` outside the change
pipeline. The recovery needs all three, in that order.

**Known IOC Baselines**

The rotation Lambda roles, populating the automation filter. They do not call
`CancelRotateSecret` in normal operation, but they do during a function replacement, which is the
dominant false positive.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | Rotation cancelled on three or more distinct secrets by one principal within thirty minutes | Correlation rule | T1098 |
| P0 | A successful `GetSecretValue` followed by `CancelRotateSecret` on the same secret by the same principal | CloudTrail | T1098 |
| P1 | `CancelRotateSecret` succeeding outside automation, with no `RotateSecret` afterwards | CloudTrail | T1098 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `CancelRotateSecret` refused — excluded by the source rule's error filter | CloudTrail | T1098 |
| P2 | `CancelRotateSecret` followed by `RotateSecret` within minutes — usually a rotation Lambda swap | CloudTrail | T1098 |
| P3 | A secret with a rotation Lambda configured whose `RotationEnabled` is false | Scheduled state check | T1098 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Classed as defence evasion | Nothing about the defender's visibility changes and the call is fully logged. What changes is that a stolen credential stops expiring | Persistence |
| Rated P3 | It is the call that makes a stolen credential permanent, and it is silent | High for one secret, critical for a sweep |
| `NOT _exists_:errorCode` | A refused `CancelRotateSecret` — an actor the permissions caught — produces no alert, and it is the one clean signal this technique offers | A rule for the refused case |
| Threshold of zero, no volume dimension | One deliberate change and a walk across the account's credentials are the same alert | A `value_count` correlation at three distinct secrets in thirty minutes |
| No notion that recovery is ordered | AWS states a cancelled rotation can block future rotations unless the orphaned `AWSPENDING` version is cleared first | Ordering made explicit in §3 |

**What the source gets right:** the event name is correctly cased, and it groups by
`userIdentity.arn`, which carries the session rather than the role name. Both kept.

**Recommended detection — rated on scope, with the refused case restored.**

```yaml
# Secrets Manager automatic rotation turned off (T1098)
#
# CANCELLING ROTATION IS PERSISTENCE, NOT EVASION. Nothing about the defender's visibility changes
# and the call is fully logged — what changes is that a value the actor already holds stops expiring.
#
# THE SOURCE RULE EXCLUDES ERRORS, so a REFUSED CancelRotateSecret — an actor the permissions caught
# — is invisible to it. That is the one clean signal this technique offers. Restored below.
#
# UNDOING THIS IS THREE CALLS. AWS warns that cancelling mid-rotation can leave VersionStage labels
# in an unexpected state, and that "failing to clean up a cancelled rotation can block you from
# starting future rotations". See ../../_ground-truth/secretsmanager.md §5.
#
# Every Secrets Manager call is a management event, so all four documents work without data events.
title: Secrets Manager automatic rotation cancelled
id: 10f9ce50-6d1e-49c4-ac0e-74f73700255d
status: experimental
description: >-
  CancelRotateSecret turns off automatic rotation and cancels any rotation in progress. Nothing
  breaks and nothing is logged as an error — the credential simply stops changing, which is what
  makes it a persistence primitive rather than an outage.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CancelRotateSecret.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  # All three keys are on the SAME event: CloudTrail writes eventSource, eventName and the outcome
  # of one API call into one record. ANDing them is correct.
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: CancelRotateSecret
    errorCode: null
  filter_automation:
    userIdentity.arn|contains: 'PlatformAutomation'
  # justified: no threshold. One cancellation on one secret is the whole technique — a second adds
  # nothing to the finding. The automation filter is the only discrimination available and it is
  # applied; rotation is otherwise cancelled by hand, under a change record.
  condition: selection and not filter_automation
falsepositives:
  - A rotation Lambda being replaced, where rotation is cancelled and re-enabled within minutes —
    check for a RotateSecret on the same secret shortly afterwards
level: high
---
# The refused case, which the source rule's error filter excludes. An actor stopped by the
# permissions is worth knowing about precisely because nothing else records the attempt.
title: Secrets Manager rotation cancellation refused
id: 3360ef6a-79f1-4a69-9fe6-5405db03c0f3
status: experimental
description: >-
  CancelRotateSecret returned an error. The source rule filters errors out, so an attempt to stop
  rotation that the permissions caught leaves no alert at all.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CancelRotateSecret.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: CancelRotateSecret
  filter_success:
    errorCode: null
  condition: selection and not filter_success
falsepositives:
  - A caller retrying against a secret that has no rotation Lambda configured, which returns an
    error of its own
level: medium
---
name: secretsmanager_rotation_cancelled
title: Secrets Manager rotation cancelled — base rule
id: 0f060caf-fad9-421b-93d2-db123772d0d6
status: informational
description: >-
  Any successful CancelRotateSecret. Base rule for the correlation below; informational alone
  because a single cancellation is already carried at high severity by the first document.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CancelRotateSecret.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: CancelRotateSecret
    errorCode: null
  condition: selection
falsepositives:
  - Rotation Lambda replacement, which cancels and re-enables within minutes
level: informational
---
# Rotation cancelled on several secrets by one principal is a sweep. The source rule thresholds at
# zero and so cannot tell one deliberate change from a walk across the account's credentials.
title: Secrets Manager rotation cancelled across multiple secrets by one principal
id: fba6ff67-5cb0-4453-aca7-56fc28e89e3b
status: experimental
description: >-
  One principal cancelled rotation on three or more distinct secrets within thirty minutes. Every
  credential involved now stays valid indefinitely, and the pattern is a sweep rather than an
  operational change.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CancelRotateSecret.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
correlation:
  type: value_count
  rules:
    - secretsmanager_rotation_cancelled
  group-by:
    - userIdentity.arn
  timespan: 30m
  condition:
    gte: 3
    field: requestParameters.secretId
falsepositives:
  - A migration off automatic rotation for a whole application, identifiable from a change record
    naming the same secrets
level: critical
```

What this set structurally cannot do: detect the quieter variant. An actor who leaves rotation
**enabled** and modifies the rotation Lambda instead gets the same outcome with a healthy status
line, and produces no Secrets Manager event at all. §2 Query 4 is where that surfaces.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> Secrets Manager is **regional**. Every call is a management event, so an empty result here
> genuinely means it did not happen.

Run Query 1 first; it establishes whether rotation is still off.

#### Query 1 — Reconstruct: was rotation restored, and was the value read first

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in CancelRotateSecret RotateSecret GetSecretValue UpdateSecretVersionStage; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | "\(.eventTime)  \(.eventName)  " +
        "result=\(if .errorCode then .errorCode else "SUCCESS" end)  " +
        "secret=\(.requestParameters.secretId // "-")  by=\(.userIdentity.arn)"'
done | sort
```

A `CancelRotateSecret` with no later `RotateSecret` on the same secret is rotation that is still off.
A `GetSecretValue` from the same principal shortly before is the credential being taken and then made
permanent — that is the P0 and it changes the response from "turn rotation back on" to "rotate the
credential at the upstream system".

#### Query 2 — Which secrets have rotation off that should not

```bash
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secrets --region "$REGION" --output json 2>/dev/null \
| jq -r '.SecretList[]
    | select(.RotationLambdaARN != null)
    | if (.RotationEnabled // false) then
        "[OK] \(.Name)  every \(.RotationRules.AutomaticallyAfterDays // "?")d  last \(.LastRotatedDate // "never")"
      else
        "[FAIL] \(.Name)  ROTATION OFF  lambda=\(.RotationLambdaARN)  last \(.LastRotatedDate // "never")"
      end'

cat <<'NOTE'

[!] Scoped to secrets that HAVE a rotation Lambda — those were rotating once, so an off state is a
    change rather than a gap. A secret with no Lambda at all was never rotating, which is a
    different and older problem and does not belong to this incident.
[!] This is a STATE check. It is the control that catches this technique when the event rule does
    not, because it survives event-name casing, principal exclusions and rules never deployed.
NOTE
```

#### Query 3 — Is an orphaned `AWSPENDING` version blocking recovery

```bash
SECRET="${1:?secret name or ARN from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
  --include-deprecated --output json 2>/dev/null \
| jq -r '.Versions | sort_by(.CreatedDate) | reverse | .[]
    | "  \(.CreatedDate)  \(.VersionId)  stages=\((.VersionStages // ["(deprecated)"]) | join(","))"'

PENDING="$(aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
  --query 'Versions[?contains(VersionStages, `AWSPENDING`)].VersionId' --output text 2>/dev/null)"
if [ -n "$PENDING" ] && [ "$PENDING" != "None" ]; then
  echo "[!] AWSPENDING is staged on $PENDING — a rotation was cancelled mid-flight."
  echo "    AWS: failing to clean this up can BLOCK future rotations. Clear it before RotateSecret."
else
  echo "[OK] no orphaned AWSPENDING version; RotateSecret should start cleanly"
fi
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

`UpdateFunctionCode` on the rotation Lambda in the same window is the quieter and worse version of
this technique: rotation stays **enabled**, `LastRotatedDate` keeps advancing, and the value written
is the actor's. Query 2 shows a healthy green line throughout, and nothing in this playbook's rules
would fire.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Nothing is failing, so there is no outage clock. The clock that matters is the credential: every hour
rotation stays off is an hour the actor's value remains live.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows a
successful `GetSecretValue` by the same principal before the cancellation, the credential is
disclosed. Re-enabling rotation is not sufficient: rotate it at the **upstream system** — the
database, the API provider — because that is where the actor's copy is valid.

#### Step 1 — Clear the orphaned rotation state

```bash
SECRET="${1:?secret name}"
REGION="${AWS_REGION:-us-east-1}"

PENDING="$(aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
  --query 'Versions[?contains(VersionStages, `AWSPENDING`)].VersionId' --output text 2>/dev/null)"

if [ -n "$PENDING" ] && [ "$PENDING" != "None" ]; then
  echo "[!] Orphaned AWSPENDING version: $PENDING"
  aws secretsmanager update-secret-version-stage --secret-id "$SECRET" \
    --version-stage AWSPENDING --remove-from-version-id "$PENDING" \
    --region "$REGION" >/dev/null 2>&1 \
    && echo "[OK] AWSPENDING cleared" \
    || echo "[FAIL] could not clear AWSPENDING — RotateSecret in Step 2 is likely to fail"
else
  echo "[OK] no orphaned AWSPENDING version"
fi
```

This step comes first for a documented reason: AWS states that failing to clean up a cancelled
rotation can block future rotations. Running Step 2 without it produces a failure that reads like a
permissions problem and sends the response down the wrong path.

#### Step 2 — Re-enable rotation and force one now

```bash
SECRET="${1:?secret name}"
REGION="${AWS_REGION:-us-east-1}"
DAYS="${2:-30}"

aws secretsmanager rotate-secret --secret-id "$SECRET" --region "$REGION" \
  --rotation-rules "AutomaticallyAfterDays=${DAYS}" >/dev/null 2>&1 \
  && echo "[OK] rotation re-enabled and an immediate rotation started" \
  || echo "[FAIL] rotate-secret failed — confirm the rotation Lambda still exists, that its resource
     policy still allows secretsmanager.amazonaws.com to invoke it, and that Step 1 cleared AWSPENDING"

aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" --output json 2>/dev/null \
| jq -r '"  rotationEnabled: \(.RotationEnabled // false)",
         "  rotationLambda:  \(.RotationLambdaARN // "none")",
         "  lastRotated:     \(.LastRotatedDate // "never")",
         "  nextRotation:    \(.NextRotationDate // "unknown")"'
```

The `describe-secret` read is the assertion, not the `rotate-secret` exit code: the call can return
success and leave rotation configured but not actually run, and `LastRotatedDate` is what settles it.

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

#### Step 4 — Rotate at the upstream system where the value was read

Re-enabling rotation replaces the value going forward. It does nothing about the copy the actor
already has, which stays valid at the database or the API provider until that system's credential is
changed. Where Query 1 shows a successful `GetSecretValue`, this step is the containment and the
Secrets Manager work is bookkeeping.

---

## 4. Eradication

### Remove Attacker Access

#### Check rotation state on a schedule, not only rotation events

A daily job that lists every secret with a rotation Lambda and asserts `RotationEnabled` is true
catches this technique regardless of event-name casing, principal exclusions or whether the rule was
ever deployed. It is the highest-value control in this playbook and it is five lines of script.

#### Alarm on `LastRotatedDate` going stale

Rotation that is enabled but failing produces exactly the same outcome as rotation that is off — a
credential that never changes — and the enabled flag reports healthy. The date is the ground truth.

#### Deny rotation control outside automation

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenySecretRotationControlOutsideAutomation",
  "Effect": "Deny",
  "Action": ["secretsmanager:CancelRotateSecret"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourRotationLambdaRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone, which here would block the legitimate cancel-then-rotate a Lambda replacement needs. Test
in a non-production OU first.

#### Guard the rotation function's code as tightly as the secret

`lambda:UpdateFunctionCode` on a rotation Lambda is equivalent to controlling every secret it
rotates, and it produces none of the Secrets Manager events this playbook watches.

---

## 5. Recovery

### Restore Clean State

#### Verify rotation is on wherever a rotation Lambda exists

```bash
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secrets --region "$REGION" --output json 2>/dev/null \
| jq -r '.SecretList[]
    | select(.RotationLambdaARN != null)
    | if (.RotationEnabled // false) then "[OK] \(.Name)  last rotated \(.LastRotatedDate // "never")"
      else "[FAIL] \(.Name) — has a rotation Lambda but rotation is OFF" end'
```

#### Verify rotation actually ran, not just that it is enabled

```bash
REGION="${AWS_REGION:-us-east-1}"
SECRET="${1:?secret name}"

LAST="$(aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" \
         --query 'LastRotatedDate' --output text 2>/dev/null)"
if [ -z "$LAST" ] || [ "$LAST" = "None" ]; then
  echo "[FAIL] $SECRET has never rotated — the enabled flag is not evidence that rotation works"
else
  echo "[OK] $SECRET last rotated $LAST"
  echo "[!] Compare against the schedule. A date older than the interval means rotation is enabled"
  echo "    and FAILING, which produces the same standing credential as rotation being off."
fi
```

#### Verify no orphaned `AWSPENDING` versions remain

```bash
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secrets --region "$REGION" --query 'SecretList[].Name' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r N; do
    [ -z "$N" ] && continue
    P="$(aws secretsmanager list-secret-version-ids --secret-id "$N" --region "$REGION" \
          --query 'Versions[?contains(VersionStages, `AWSPENDING`)].VersionId' --output text 2>/dev/null)"
    if [ -n "$P" ] && [ "$P" != "None" ]; then
      echo "[FAIL] $N — AWSPENDING still staged on $P; future rotations may refuse to start"
    else
      echo "[OK] $N"
    fi
  done
```

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"
SECRET="${1:?a NON-PRODUCTION secret that has rotation configured}"

# Cancel and immediately restore. This exercises the rule without leaving anything off, and the
# restore is the same sequence §3 uses.
aws secretsmanager cancel-rotate-secret --secret-id "$SECRET" --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] rotation cancelled — expect the HIGH alert within 15 min" \
  || echo "[!] cancel failed; the secret may not have rotation configured"

sleep 30
P="$(aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
      --query 'Versions[?contains(VersionStages, `AWSPENDING`)].VersionId' --output text 2>/dev/null)"
[ -n "$P" ] && [ "$P" != "None" ] && aws secretsmanager update-secret-version-stage \
  --secret-id "$SECRET" --version-stage AWSPENDING --remove-from-version-id "$P" \
  --region "$REGION" >/dev/null 2>&1 && echo "[OK] AWSPENDING cleared"

aws secretsmanager rotate-secret --secret-id "$SECRET" --region "$REGION" \
  --rotation-rules AutomaticallyAfterDays=30 >/dev/null 2>&1 \
  && echo "[OK] rotation restored" || echo "[FAIL] restore failed — investigate before leaving this"
echo "[!] If the cancellation produced no alert, your coverage is the source rule as written: a P3"
echo "    that excludes errors and cannot distinguish one secret from thirty."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was rotation restored, and how long was it off? | Every hour it stays off is an hour the actor's copy remains the live credential. |
| Did the same principal read the value first? | Read-then-cancel is a stolen credential being made permanent, and the fix is upstream, not in Secrets Manager. |
| How many secrets were affected? | One is a finding; three is a sweep across the account's credentials. |
| Was an `AWSPENDING` version left orphaned? | AWS states this can block future rotations, so the incident quietly outlives the response. |
| Was the rotation Lambda modified instead? | Rotation left enabled with a tampered function is the same outcome with a healthy status line. |
| Is `LastRotatedDate` advancing? | Rotation enabled but failing produces the same standing credential as rotation off. |

### Recommended Guardrails

**Check rotation state on a schedule.** It survives event-name casing, principal exclusions and
rules that were never deployed — every way an event rule fails.

**Alarm on `LastRotatedDate` going stale.** The enabled flag is not evidence that rotation works.

**Clear `AWSPENDING` before restarting rotation.** Skipping it produces a failure that reads like a
permissions problem.

**Alert on refused cancellations.** The source rule's error filter hides the one clean signal this
technique produces.

**Guard the rotation Lambda's code.** `lambda:UpdateFunctionCode` on it is equivalent to controlling
every secret it rotates.

### Technique Reference

**T1098 — Account Manipulation.** Verified live at https://attack.mitre.org/techniques/T1098/ on
2026-08-31. It covers any action that preserves or modifies adversary access, which is exactly what
stopping a credential from rotating does.

Cancelling rotation changes no defensive visibility and is fully logged, which is why it is mapped
to Persistence rather than to a defence-impairment technique.

AWS references relied on throughout, all verified 2026-08-30:

- `CancelRotateSecret` — that it turns off automatic rotation, can leave `VersionStage` labels in an
  unexpected state, and that failing to clean up a cancelled rotation can block future rotations:
  https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CancelRotateSecret.html
- Secrets Manager CloudTrail logging — all API calls recorded as management events:
  https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html

Service-wide verified behaviour shared by every `secretsmanager.*` playbook is in
`../_ground-truth/secretsmanager.md`.

### Residual Risk

**A tampered rotation Lambda defeats every rule here.** Rotation stays enabled,
`LastRotatedDate` advances, and the value written is the actor's. Nothing in Secrets Manager's event
stream distinguishes it from a healthy rotation.

**Re-enabling rotation does not invalidate the copy already taken.** Until the upstream system's
credential is changed, the actor's value keeps working.

**Rotation enabled but failing looks identical to rotation working.** Only `LastRotatedDate`
separates them, and nothing alarms on it by default.

**The dominant false positive and the technique share a signature.** A rotation Lambda replacement
legitimately cancels and re-enables; so does an actor who wants to look like one. The distinguishing
evidence is a change record, not an event.
