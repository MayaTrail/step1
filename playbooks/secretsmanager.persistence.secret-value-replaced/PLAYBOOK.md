# IR Playbook: Secrets Manager Secret Value Replaced — `PutSecretValue` and the path that writes nothing

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence — the value an application authenticates with is replaced, so the credential in use becomes one the actor chose |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High when `AWSCURRENT` is moved to an existing version, when the KMS key changes, or when values are replaced across several secrets; medium for a single replacement outside automation or a refused write. The source rule is P3 and cannot fire. |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1556 (primary); T1565.001 (the destructive shape) |
| Services in Scope | Secrets Manager, KMS, CloudTrail |

**What the technique does:** the actor makes the credential they chose the operative one. Three
different calls do it:

| Call | Effect |
|---|---|
| `UpdateSecret` | New version, `AWSCURRENT` moves to it |
| `PutSecretValue` | New version, `AWSCURRENT` moves to it — what the SDKs and rotation Lambdas call |
| `UpdateSecretVersionStage` | **Writes nothing** — `AWSCURRENT` moves to a version that already exists |

**Why the usual reflexes miss it.** The first is the event name: the source rule is lowercase and
cannot fire. The second is that it watches the least-used of the three paths. The third is the
quietest path, `UpdateSecretVersionStage`, which needs no permission to write the secret and produces
no write event. The fourth is the error filter, which hides the write the permissions caught.

**Detection thesis:** cover all three paths, rate the one that writes nothing highest, and restore
the refused case.

**Adjacent playbooks.** Rotation being turned off — the other way to keep a value operative — is
`../secretsmanager.persistence.rotation-disabled/`. Deletion is
`../secretsmanager.impact.secret-deleted/`. Enumeration is
`../secretsmanager.discovery.secrets-enumerated/` and
`../secretsmanager.discovery.access-repeatedly-denied/`. A resource policy opened on a secret is
`../secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. AWS records **all** Secrets Manager API calls as
management events, so every one of the three paths is captured by default — see
`../_ground-truth/secretsmanager.md` §1.

**A record of which workloads consume which secret.** CloudTrail never records a value, so the
question "what took the replacement" is answered from a consumer inventory, not from the log.

**A recorded KMS key per secret.** `UpdateSecret` can change `KmsKeyId`, which changes who can
decrypt the secret at rest while it stays "encrypted" and a compliance check still passes.

**Alerting (must be pre-configured)**

- **`UpdateSecretVersionStage` moving `AWSCURRENT` outside automation → P0**
- **`UpdateSecret` changing `KmsKeyId` outside automation → P1**
- **Values replaced across three or more secrets by one principal in thirty minutes → P1**
- **`UpdateSecret`, `PutSecretValue` or `UpdateSecretVersionStage` refused → P2**

**Response Tooling**

An IAM principal that can call `secretsmanager list-secret-version-ids`,
`secretsmanager get-secret-value --version-id` and `secretsmanager update-secret-version-stage`
outside the change pipeline. The rollback needs all three.

**Known IOC Baselines**

The rotation Lambda and deployment roles, populating the automation filter. They call
`PutSecretValue` and `UpdateSecretVersionStage` constantly and by design; without the filter the
write rules are unusable.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `UpdateSecretVersionStage` moving `AWSCURRENT` outside automation — no value was written | CloudTrail | T1556 |
| P1 | `UpdateSecret` changing `KmsKeyId` outside automation — who can decrypt at rest changes | CloudTrail | T1556 |
| P1 | Values replaced across three or more distinct secrets by one principal within thirty minutes | Correlation rule | T1556 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `UpdateSecret` or `PutSecretValue` outside automation | CloudTrail | T1556 |
| P2 | A write refused — excluded by the source rule's error filter | CloudTrail | T1556 |
| P3 | A successful `GetSecretValue` shortly before a replacement, by the same principal | CloudTrail | T1556 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"updatesecret"` — lowercase | CloudTrail emits `UpdateSecret`. On a case-sensitive field the rule matches nothing and **cannot fire** | Documented casing |
| Watches `UpdateSecret` alone | `PutSecretValue` is what the SDKs and rotation Lambdas call, and `UpdateSecretVersionStage` changes the operative value without writing one. Two of three paths unmonitored | All three covered, with the staging move rated highest |
| `NOT _exists_:errorCode` | A denied write — an actor the permissions caught — produces no alert | A rule for the refused case |
| No content check on `UpdateSecret` | The same call can change `KmsKeyId`, altering who can decrypt at rest while the secret stays encrypted | A `KmsKeyId` dimension in the query and a P1 trigger |
| Threshold of zero, no volume dimension | One replacement and a walk across the account's secrets are the same alert | A `value_count` correlation at three distinct secrets in thirty minutes |
| Tactic TA0005 | Nothing about the defender's visibility changes. What changes is the material an application authenticates with | Persistence, `T1556` |

**What the source gets right:** it groups by `userIdentity.arn`, which carries the session rather
than the role name. Kept.

**Recommended detection — all three paths, with the one that writes nothing rated highest.**

```yaml
# Secrets Manager secret value replaced (T1556)
#
# THE RULE CANNOT FIRE. It matches `eventName:"updatesecret"`; CloudTrail emits `UpdateSecret`, and
# on a case-sensitive field the lowercase form matches nothing. Eleventh instance of that defect
# class across the source set — see ../../_ground-truth/secretsmanager.md §7.
#
# AND `UpdateSecret` IS ONE OF THREE WRITE PATHS, AND NOT THE ONE THE SDKs USE. `PutSecretValue`
# writes a new version and moves AWSCURRENT to it — it is what the AWS SDKs and rotation Lambdas
# call. `UpdateSecretVersionStage` writes NOTHING; it moves AWSCURRENT to a version that already
# exists, so an actor who once staged a value can make it operative again with no permission to write
# the secret and no write event at all. See ../../_ground-truth/secretsmanager.md §6.
#
# IT EXCLUDES ERRORS, so a denied write — an actor the permissions caught — produces no alert.
#
# Every Secrets Manager call is a management event, so all four documents work without data events.
# Rotation being turned off is a different use case and lives in
# ../../secretsmanager.persistence.rotation-disabled/.
title: Secrets Manager AWSCURRENT moved to an existing version
id: 61736bf9-db20-4ed2-ad73-4441d42dc9fd
status: experimental
description: >-
  UpdateSecretVersionStage moved the AWSCURRENT label to a version that already existed. No value was
  written, so no write path fired and no permission to write the secret was needed — an actor who
  once had a value staged can make it operative again this way.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_UpdateSecretVersionStage.html
  - https://attack.mitre.org/techniques/T1556/
tags:
  - attack.persistence
  - attack.t1556
logsource:
  product: aws
  service: cloudtrail
detection:
  # All four keys are on the SAME event: CloudTrail writes eventSource, eventName, the request body
  # and the outcome of one API call into one record. ANDing them is correct.
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: UpdateSecretVersionStage
    requestParameters.versionStage: AWSCURRENT
    errorCode: null
  filter_automation:
    userIdentity.arn|contains:
      - 'PlatformAutomation'
      - 'SecretsRotationFunction'
  condition: selection and not filter_automation
falsepositives:
  - An operator rolling a secret back to AWSPREVIOUS after a bad deployment, which is the same call
    used for exactly the right reason — confirm against a change record
level: high
---
name: secretsmanager_secret_value_written
title: Secrets Manager secret value written
id: baebb5d1-9e1b-4d5d-9827-f77e9edb64eb
status: experimental
description: >-
  UpdateSecret or PutSecretValue wrote a new version outside the automation allowlist. Informational
  alone — applications and pipelines write secrets legitimately. Base rule for the correlation below.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html
  - https://attack.mitre.org/techniques/T1556/
tags:
  - attack.persistence
  - attack.t1556
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName:
      - UpdateSecret
      - PutSecretValue
    errorCode: null
  filter_automation:
    userIdentity.arn|contains:
      - 'PlatformAutomation'
      - 'SecretsRotationFunction'
  condition: selection and not filter_automation
falsepositives:
  - Deployment pipelines that seed secret values — add the role to the allowlist rather than removing
    this document
  - Operators updating a credential by hand after an upstream change
level: informational
---
# The refused case, which the source rule's error filter excludes.
title: Secrets Manager secret write refused
id: 0b1994f5-d493-48d4-86b1-b1a592b99be2
status: experimental
description: >-
  UpdateSecret, PutSecretValue or UpdateSecretVersionStage returned an error. The source rule filters
  errors out, so a write the permissions caught leaves no alert at all.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_UpdateSecret.html
  - https://attack.mitre.org/techniques/T1556/
tags:
  - attack.persistence
  - attack.t1556
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName:
      - UpdateSecret
      - PutSecretValue
      - UpdateSecretVersionStage
  filter_success:
    errorCode: null
  condition: selection and not filter_success
falsepositives:
  - A workload deployed before its policy grant, which repeats against one secret id rather than
    walking several
level: medium
---
# Values replaced across several secrets by one principal is a sweep. The source rule thresholds at
# zero and cannot express it.
title: Secrets Manager values replaced across multiple secrets by one principal
id: 279fae34-fdf0-44b3-b4e1-0080b65e7045
status: experimental
description: >-
  One principal wrote new values into three or more distinct secrets within thirty minutes, outside
  automation. Every consumer of every one of those secrets will pick up the new value on its next
  fetch.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html
  - https://attack.mitre.org/techniques/T1556/
tags:
  - attack.persistence
  - attack.t1556
correlation:
  type: value_count
  rules:
    - secretsmanager_secret_value_written
  group-by:
    - userIdentity.arn
  timespan: 30m
  condition:
    gte: 3
    field: requestParameters.secretId
falsepositives:
  - A credential-rotation exercise run by hand across an application's secrets, identifiable from a
    change record naming the same secrets
level: high
```

What this set structurally cannot do: tell you what the new value is. CloudTrail never records
Secrets Manager values, so whether the replacement is attacker-controlled is established from the
version chain and the consumer side, never from the log — see `../_ground-truth/secretsmanager.md` §2.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> Secrets Manager is **regional**. Every call is a management event, so an empty result here
> genuinely means it did not happen.

Run Query 1 first; it establishes which of the three paths was used.

#### Query 1 — Reconstruct: which path, and was the value read first

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in UpdateSecret PutSecretValue UpdateSecretVersionStage GetSecretValue; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | .requestParameters as $r
      # UpdateSecretVersionStage writes NO value — it moves AWSCURRENT to a version that already
      # exists, so it needs no permission to write the secret and produces no new version.
      | (if .eventName == "UpdateSecretVersionStage"
         then "stage=\($r.versionStage // "-") move=\($r.moveToVersionId // "-") from=\($r.removeFromVersionId // "-")"
         elif (($r.kmsKeyId // "") != "") then "kmsKeyId=\($r.kmsKeyId)"
         else "-" end) as $detail
      | "\(.eventTime)  \(.eventName)  " +
        "result=\(if .errorCode then .errorCode else "SUCCESS" end)  " +
        "secret=\($r.secretId // "-")  \($detail)  by=\(.userIdentity.arn)"'
done | sort
```

A line naming `stage=AWSCURRENT` is the quiet path — the operative value changed and nothing was
written. A `kmsKeyId=` line means who can decrypt the secret at rest changed while it stayed
encrypted. A `GetSecretValue` shortly before, by the same principal, is the previous value being
taken before it was replaced.

#### Query 2 — Read the version chain and recover the previous value

```bash
SECRET="${1:?secret name or ARN from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
  --include-deprecated --output json 2>/dev/null \
| jq -r '.Versions | sort_by(.CreatedDate) | reverse | .[]
    | "  \(.CreatedDate)  \(.VersionId)  stages=\((.VersionStages // ["(deprecated)"]) | join(","))"'

cat <<'NOTE'

[!] Secrets Manager keeps 100 of the most recent versions and ALL versions from the last 24 hours,
    so the value operative before the change is still reachable:
      aws secretsmanager get-secret-value --secret-id <secret> --version-id <id>
    AWSPREVIOUS is only one version deep, but the versions behind it are not gone.
[!] READ THE DATES. A version created at the time of the incident that now holds AWSCURRENT is a
    replacement. A version created LONG ago that now holds AWSCURRENT means the LABEL was moved
    rather than a value written — that is the UpdateSecretVersionStage path.
NOTE
```

#### Query 3 — Who consumed the replacement, and did the KMS key change

```bash
SECRET="${1:?secret name or ARN}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

echo "=== current encryption ==="
aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" --output json 2>/dev/null \
| jq -r '"  kmsKeyId: \(.KmsKeyId // "aws/secretsmanager (AWS-managed default)")",
         "  rotation: \(.RotationEnabled // false)",
         "  lastChanged: \(.LastChangedDate // "unknown")"'

echo "=== principals that read this secret since the change ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg s "$SECRET" '[.Events[].CloudTrailEvent | fromjson
    | select((.requestParameters.secretId // "") | contains($s))
    | select(.errorCode == null) | .userIdentity.arn] | group_by(.)
  | map("  \(length)x  \(.[0])") | .[]'

echo
echo "[!] Every principal listed took whatever value was current when it read. Those are the"
echo "    workloads now authenticating with the replacement, and the list is the blast radius —"
echo "    CloudTrail cannot tell you what they received, only that they received something."
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

`CancelRotateSecret` in the same window is the pair to this technique: write the value, then stop it
being replaced. That half is `../secretsmanager.persistence.rotation-disabled/`, and the two
together are a credential made permanent.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Roll the label back before investigating. The previous version is retained, so the rollback is a
lookup and one call — but every consumer that fetches in the meantime takes the replacement.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 4 shows
`CancelRotateSecret` on the same secret, go to `../secretsmanager.persistence.rotation-disabled/`
after the rollback: rotation must be restored or the value you roll back to never changes either.

#### Step 1 — Move `AWSCURRENT` back to the previous version

```bash
SECRET="${1:?secret name}"
PREV_VERSION="${2:?version id from Query 2 that held AWSCURRENT before the change}"
REGION="${AWS_REGION:-us-east-1}"

CURRENT="$(aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
  --query 'Versions[?contains(VersionStages, `AWSCURRENT`)].VersionId' --output text 2>/dev/null)"
echo "AWSCURRENT is currently: ${CURRENT:-unknown}"
echo "Moving AWSCURRENT to:    $PREV_VERSION"

if [ -z "$CURRENT" ] || [ "$CURRENT" = "None" ]; then
  echo "[FAIL] cannot read the current version — resolve access before proceeding"
else
  read -r -p "Proceed? [y/N] " ANS
  if [ "$ANS" = "y" ]; then
    aws secretsmanager update-secret-version-stage --secret-id "$SECRET" --version-stage AWSCURRENT \
      --move-to-version-id "$PREV_VERSION" --remove-from-version-id "$CURRENT" \
      --region "$REGION" >/dev/null 2>&1 \
      && echo "[OK] AWSCURRENT moved back" || echo "[FAIL] the move did not apply"
    aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
      --query 'Versions[?contains(VersionStages, `AWSCURRENT`)].VersionId' --output text 2>/dev/null \
      | sed 's/^/  AWSCURRENT is now: /'
  fi
fi
```

The final read is the assertion, not the exit code. Consumers cache secret values, so "recovered" in
Secrets Manager is not "recovered" in a running process until its cache expires — which can be hours.

#### Step 2 — Contain the principal

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

#### Step 3 — Restore the KMS key if it changed

```bash
SECRET="${1:?secret name}"
EXPECTED_KEY="${2:?the KMS key id or ARN this secret should use, from your baseline}"
REGION="${AWS_REGION:-us-east-1}"

NOW="$(aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" \
        --query 'KmsKeyId' --output text 2>/dev/null)"
echo "current key: ${NOW:-aws/secretsmanager}"
if [ "$NOW" = "$EXPECTED_KEY" ]; then
  echo "[OK] key matches the baseline"
else
  echo "[FAIL] key differs from the baseline — who can decrypt this secret at rest has changed."
  echo "    Restore with:"
  echo "    aws secretsmanager update-secret --secret-id $SECRET --kms-key-id $EXPECTED_KEY --region $REGION"
  echo "[!] Changing the key back does NOT re-encrypt existing versions. New versions use the new"
  echo "    key; versions written under the actor's key still require it to read."
fi
```

#### Step 4 — Rotate at the upstream system

If the replaced value was a working credential, the actor knows it. Rolling `AWSCURRENT` back
restores what the application uses; it does not invalidate what the actor holds. Change the
credential at the database or the API provider, then write the new value in.

---

## 4. Eradication

### Remove Attacker Access

#### Treat the three write paths as one capability

`secretsmanager:UpdateSecret`, `secretsmanager:PutSecretValue` and
`secretsmanager:UpdateSecretVersionStage` are one capability, not three. A policy that grants the
first two and omits the third leaves the path that needs no value-write permission wide open, and it
is the one least likely to be noticed in a review.

#### Deny the write paths outside automation

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenySecretWritesOutsideAutomation",
  "Effect": "Deny",
  "Action": ["secretsmanager:PutSecretValue",
             "secretsmanager:UpdateSecret",
             "secretsmanager:UpdateSecretVersionStage"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourRotationLambdaRole",
                                        "arn:aws:iam::*:role/YourDeployRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. All three role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone, which here would stop rotation itself. Confirm the rotation Lambda's execution role is on
the list before attaching, and test in a non-production OU first.

#### Alarm on a `KmsKeyId` change

`UpdateSecret` can change it, the secret stays encrypted, and every compliance check keeps passing.
The only signal is the request parameter.

#### Record the expected `AWSCURRENT` version id per secret

A drift check comparing the recorded id against the live one catches the
`UpdateSecretVersionStage` path directly, without depending on catching the event.

---

## 5. Recovery

### Restore Clean State

#### Verify `AWSCURRENT` points where it should

```bash
REGION="${AWS_REGION:-us-east-1}"
SECRET="${1:?secret name}"
EXPECTED="${2:?the version id that should hold AWSCURRENT}"

NOW="$(aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
  --query 'Versions[?contains(VersionStages, `AWSCURRENT`)].VersionId' --output text 2>/dev/null)"
if [ -z "$NOW" ] || [ "$NOW" = "None" ]; then
  echo "[FAIL] no version holds AWSCURRENT — GetSecretValue will fail for every consumer"
elif [ "$NOW" = "$EXPECTED" ]; then
  echo "[OK] AWSCURRENT is $NOW"
else
  echo "[FAIL] AWSCURRENT is $NOW, expected $EXPECTED"
fi
```

The first branch is not hypothetical: clearing a staging label without moving it leaves a secret that
exists, describes cleanly, and cannot be read.

#### Verify consumers have picked up the restored value

```bash
REGION="${AWS_REGION:-us-east-1}"
SECRET="${1:?secret name}"
SINCE="${2:?ISO8601 timestamp of the rollback, e.g. 2026-08-31T10:00:00Z}"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg s "$SECRET" '[.Events[].CloudTrailEvent | fromjson
    | select((.requestParameters.secretId // "") | contains($s))
    | select(.errorCode == null) | .userIdentity.arn] | unique
  | if length == 0 then "[!] NO consumer has re-fetched since the rollback — they are still running
    on the replacement until their caches expire"
    else (.[] | "[OK] re-fetched: \(.)") end'
```

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"
SECRET="${1:?a NON-PRODUCTION secret name}"

# Exercise the QUIET path — moving AWSCURRENT to an existing version without writing one. If this
# produces no alert, coverage is still the source rule's single UpdateSecret match and the path that
# needs no write permission is unmonitored.
CUR="$(aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
       --query 'Versions[?contains(VersionStages, `AWSCURRENT`)].VersionId' --output text 2>/dev/null)"
PREV="$(aws secretsmanager list-secret-version-ids --secret-id "$SECRET" --region "$REGION" \
        --query 'Versions[?contains(VersionStages, `AWSPREVIOUS`)].VersionId' --output text 2>/dev/null)"

if [ -z "$PREV" ] || [ "$PREV" = "None" ]; then
  echo "[!] $SECRET has no AWSPREVIOUS version — write one value first, then rerun"
else
  aws secretsmanager update-secret-version-stage --secret-id "$SECRET" --version-stage AWSCURRENT \
    --move-to-version-id "$PREV" --remove-from-version-id "$CUR" --region "$REGION" >/dev/null 2>&1 \
    && echo "[OK] AWSCURRENT moved — expect the HIGH staging alert, not a generic write alert"
  sleep 30
  aws secretsmanager update-secret-version-stage --secret-id "$SECRET" --version-stage AWSCURRENT \
    --move-to-version-id "$CUR" --remove-from-version-id "$PREV" --region "$REGION" >/dev/null 2>&1 \
    && echo "[OK] moved back"
fi
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Which of the three paths moved `AWSCURRENT`? | `UpdateSecretVersionStage` needs no permission to write the secret and fires no write rule. |
| Was the version now current created recently, or long ago? | A long-ago version holding `AWSCURRENT` means the label was moved, not a value written. |
| Did the `KmsKeyId` change too? | Who can decrypt the secret at rest changes while it stays encrypted and compliance still passes. |
| Which consumers fetched after the change? | They are the blast radius, and CloudTrail records only that they fetched, never what they got. |
| Did the same principal read the value first? | The previous credential was taken before it was replaced. |
| Was rotation also cancelled? | Write the value, then stop it changing — the two together make the credential permanent. |

### Recommended Guardrails

**Treat the three write paths as one capability.** Granting `UpdateSecret` and `PutSecretValue`
while forgetting `UpdateSecretVersionStage` leaves the quietest path open.

**Record the expected `AWSCURRENT` version id and drift-check it.** That catches the staging path
directly, without depending on catching the event.

**Alarm on `KmsKeyId` changes.** The secret stays encrypted, so nothing else will tell you.

**Alert on refused writes.** The source rule's error filter hides the attempt the permissions caught.

**Remember consumers cache.** A rollback is not effective until they re-fetch, and the recovery check
has to prove that rather than assume it.

### Technique Reference

**T1556 — Modify Authentication Process.** Verified live at
https://attack.mitre.org/techniques/T1556/ on 2026-08-31. Replacing a secret replaces the material an
application authenticates with, which is what this technique names.

**T1565.001 — Data Manipulation: Stored Data Manipulation.** Verified live 2026-08-31. It covers the
purely destructive shape, where the replacement is not a working credential and the application
simply breaks.

The source rule maps `T1098` under TA0005. The technique is defensible; the tactic is not, because
nothing about the defender's visibility changes — this is persistence.

AWS references relied on throughout, all verified 2026-08-30:

- `PutSecretValue` — automatic `AWSCURRENT`/`AWSPREVIOUS` movement, and that Secrets Manager keeps
  100 versions plus everything from the last 24 hours:
  https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html
- `UpdateSecretVersionStage` — moving `AWSCURRENT` to an existing version without writing one:
  https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_UpdateSecretVersionStage.html
- `UpdateSecret` — that it also modifies `KmsKeyId` and `Description`:
  https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_UpdateSecret.html

Service-wide verified behaviour shared by every `secretsmanager.*` playbook is in
`../_ground-truth/secretsmanager.md`.

### Residual Risk

**CloudTrail never records the value.** Whether a replacement is attacker-controlled is inferred from
the version chain and the principal, never confirmed from the log.

**Consumers cache secret values.** Moving `AWSCURRENT` back does not change what a running process
holds until its cache expires, and nothing reports which processes are still on the old fetch.

**Changing the KMS key back does not re-encrypt existing versions.** Versions written under the
actor's key still require that key to read, so a rollback can leave part of the chain unreadable.

**The version quota is a slow denial.** Writing more than once every ten minutes creates versions
faster than Secrets Manager removes them, and a secret at its version limit stops accepting new
values — including the one meant to recover it.
