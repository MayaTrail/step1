# IR Playbook: Secrets Manager Secret Deleted — `DeleteSecret` denies access before it destroys

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Impact — credential material is scheduled for deletion or destroyed outright, and every consumer of it stops working at once |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when `ForceDeleteWithoutRecovery` was used, because nothing restores it; high for bulk deletion; medium for a single windowed deletion. The source rule is P3 and cannot fire. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485 (primary); T1489 (the immediate consumer outage) |
| Services in Scope | Secrets Manager, CloudTrail |

**What the technique does:** the actor deletes credential material. The call has two shapes and they
are not the same incident:

| Call | Outcome |
|---|---|
| `DeleteSecret` (default) | 30-day recovery window, `RestoreSecret` undoes it |
| `DeleteSecret --force-delete-without-recovery` | No window, no restore, gone |

**Why the usual reflexes miss it.** The first is the event name: the source rule is lowercase and
cannot fire. The second is the missing content check — a reversible deletion and a permanent one
arrive as one alert. The third is the biggest: reading "30-day recovery window" as "we have time".
AWS is explicit that a secret scheduled for deletion **cannot be retrieved**, so the outage starts on
the spot and the thirty days apply only to recovering the value. The fourth is a rule written as
`NOT forceDeleteWithoutRecovery:"false"`, which matches every ordinary deletion because the parameter
is simply absent when omitted.

**Detection thesis:** read the request body, rate on reversibility, and treat every deletion as an
availability incident that has already begun.

**Adjacent playbooks.** A value read before the deletion is
`../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`.
Enumeration that preceded it is `../secretsmanager.discovery.secrets-enumerated/`. Rotation turned
off is `../secretsmanager.persistence.secret-value-replaced/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. AWS records **all** Secrets Manager API calls as
management events, so nothing needs purchasing — see `../_ground-truth/secretsmanager.md` §1.

**An inventory of which workload consumes which secret**, maintained outside Secrets Manager. Once a
secret is scheduled for deletion its consumers are already failing, and the fastest way to scope the
outage is a list you wrote earlier rather than one you derive under pressure.

**A copy of every secret's rotation configuration and resource policy.** Deletion takes both with it.
`RestoreSecret` brings them back, but a force-deleted secret has to be rebuilt from something.

**Alerting (must be pre-configured)**

- **`DeleteSecret` with `ForceDeleteWithoutRecovery: true` → P0**
- **A successful `GetSecretValue` followed by a deletion of the same secret by the same principal → P0**
- **Three or more distinct secrets scheduled for deletion by one principal in thirty minutes → P1**
- **`DeleteSecret` with `RecoveryWindowInDays: 7`, the minimum → P2**
- **Any successful `DeleteSecret` outside the decommissioning path → P2**

**Response Tooling**

An IAM principal that can call `secretsmanager restore-secret` and `describe-secret` outside the
change pipeline. `RestoreSecret` is the containment step and it must not be gated behind the process
that may have caused the incident.

**Known IOC Baselines**

The roles that legitimately decommission secrets. Note that automation should be *excluded from the
base rule and not from the force-deletion rule* — a pipeline that tears down environments uses the
default window precisely so mistakes are recoverable, so a pipeline force-deleting is itself the
finding.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `DeleteSecret` with `ForceDeleteWithoutRecovery: true` | CloudTrail | T1485 |
| P0 | A successful `GetSecretValue` followed by a deletion of the same secret by the same principal | CloudTrail | T1485 |
| P1 | Three or more distinct secrets scheduled for deletion by one principal in thirty minutes | Correlation rule | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `DeleteSecret` with `RecoveryWindowInDays: 7` — the minimum, chosen over the default | CloudTrail | T1485 |
| P2 | Any successful `DeleteSecret` outside the decommissioning path | CloudTrail | T1489 |
| P3 | `DeleteSecret` refused — an attempt that the permissions caught | CloudTrail | T1485 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"deletesecret"` — lowercase | CloudTrail emits `DeleteSecret`. On a case-sensitive field the rule matches nothing and **cannot fire** | Documented casing |
| No content check on the request body | A deletion reversible for thirty days and one that is permanent arrive as the same alert | Separate rules for `ForceDeleteWithoutRecovery` and for the seven-day minimum |
| Threshold of zero, so no volume dimension | The rule cannot express "this is a sweep rather than a decommission" | A `value_count` correlation at three distinct secrets in thirty minutes |
| `T1528 — Steal Application Access Token` under Credential Access | Deleting a secret steals nothing. It destroys | `T1485 — Data Destruction`, with `T1489` for the consumer outage |
| Successes and refusals rated identically | A refused deletion is the permissions working; a successful one is an outage in progress | Rated apart |
| Automation excluded from the whole rule | A pipeline that force-deletes is exactly the case worth seeing, and the exclusion hides it | Automation excluded from the base rule only |

**Recommended detection — reversibility read from the request body, not inferred.**

```yaml
# Secrets Manager secret deleted (T1485)
#
# THE RULE CANNOT FIRE. It matches `eventName:"deletesecret"`; CloudTrail emits `DeleteSecret`, and on
# a case-sensitive field the lowercase form matches nothing. Tenth instance of that defect class
# across the source set — see ../../_ground-truth/secretsmanager.md §7.
#
# IT HAS NO CONTENT CHECK ON THE ONE PARAMETER THAT DECIDES THE INCIDENT. A default DeleteSecret is
# reversible with RestoreSecret for 7 to 30 days. `ForceDeleteWithoutRecovery: true` is permanent.
# Those are different incidents and the source rule reports them identically.
#
# BEWARE THE ABSENT PARAMETER. `forceDeleteWithoutRecovery` and `recoveryWindowInDays` are optional,
# so they are simply MISSING from requestParameters when the caller omits them. A rule written as
# `NOT forceDeleteWithoutRecovery:"false"` would match every ordinary deletion; the documents below
# match on the value `true` being present, never on the absence of `false`.
#
# AND THE RECOVERY WINDOW IS NOT AN OUTAGE WINDOW. AWS: "When a secret is scheduled for deletion, you
# cannot retrieve the secret value." Consumers start failing the moment the call succeeds. The thirty
# days are for recovering the VALUE, not for keeping the service up.
#
# Every Secrets Manager call is a management event, so all four documents work without data events.
title: Secrets Manager secret force-deleted without recovery
id: 9992193a-caf6-45eb-a1a8-13fd03007dce
status: experimental
description: >-
  DeleteSecret was called with ForceDeleteWithoutRecovery true. There is no recovery window and
  RestoreSecret will not work — the credential material is gone. The source rule reports this
  identically to a routine deletion that is reversible for thirty days.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  # All three keys are on the SAME event: CloudTrail writes eventSource, eventName and the request
  # body of one API call into one record. ANDing them is correct.
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: DeleteSecret
    requestParameters.forceDeleteWithoutRecovery: true
  # justified: no threshold and no allowlist. A single irreversible deletion of credential material is
  # the finding; there is no second one that makes it worse. Automation does not force-delete —
  # pipelines that tear down environments use the default window precisely so that a mistake is
  # recoverable, so an automation-role exclusion here would only hide the case worth seeing.
  condition: selection
falsepositives:
  - Test-environment teardown that deliberately reuses secret names immediately, which is the one
    legitimate reason to skip the window
level: critical
---
name: secretsmanager_secret_deleted
title: Secrets Manager secret scheduled for deletion
id: e69a7f2b-0ef9-48d9-bac5-c32548023045
status: experimental
description: >-
  DeleteSecret succeeded with a recovery window. Reversible with RestoreSecret until the DeletionDate
  — but the value cannot be retrieved from the moment this call succeeds, so consumers are already
  failing. Base rule for the correlation below.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: DeleteSecret
    errorCode: null
  filter_automation:
    userIdentity.arn|contains: 'PlatformAutomation'
  condition: selection and not filter_automation
falsepositives:
  - Decommissioning work, which is the common explanation and is confirmed by a change record rather
    than by the event
level: low
---
# A compressed window is a deliberate choice. Seven days is the minimum Secrets Manager allows, so a
# caller who sets it has read the documentation and decided to shorten the time you have.
title: Secrets Manager secret deleted with the minimum recovery window
id: d609f56b-a210-4212-a289-a996ebc72b11
status: experimental
description: >-
  DeleteSecret was called with a recovery window of seven days, the shortest Secrets Manager permits.
  Routine decommissioning takes the thirty-day default; setting the floor narrows the window for
  recovery on purpose.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: DeleteSecret
    requestParameters.recoveryWindowInDays: 7
  # justified: the parameter is optional and defaults to thirty. Its presence at the floor value is
  # the signal, so there is nothing to threshold and no allowlist that would not hide it.
  condition: selection
falsepositives:
  - An environment-teardown pipeline standardised on the minimum window — confirm once, then add the
    role to the base rule's automation filter rather than removing this document
level: medium
---
# Three or more distinct secrets in thirty minutes. The source rule has a threshold of zero, so it
# cannot express "this is a sweep rather than a decommission".
title: Secrets Manager secrets deleted in bulk by one principal
id: bfc7ec39-a5b7-4b8f-b450-c50fbbf9dfad
status: experimental
description: >-
  One principal scheduled three or more distinct secrets for deletion within thirty minutes. Bulk
  deletion of credential material is destruction rather than decommissioning, and every consumer of
  every one of those secrets is already failing.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: value_count
  rules:
    - secretsmanager_secret_deleted
  group-by:
    - userIdentity.arn
  timespan: 30m
  condition:
    gte: 3
    field: requestParameters.secretId
falsepositives:
  - A planned decommission of an entire environment, which should be identifiable from a change
    record naming the same secrets
level: high
```

What this set structurally cannot do: tell you what the secret held. CloudTrail never records
Secrets Manager response bodies, so a force-deleted secret's value is unrecoverable from the log as
well as from the service — see `../_ground-truth/secretsmanager.md` §2.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> Secrets Manager is **regional**. Every call is a management event, so an empty result here
> genuinely means it did not happen.

**Run §3 Step 1 before Query 1 if any deletion was windowed.** The restore is one call, it is
reversible, and the window is the only thing in this incident with a deadline.

#### Query 1 — Reconstruct: which secrets, and was recovery possible

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in DeleteSecret RestoreSecret GetSecretValue; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | .requestParameters as $r
      # forceDeleteWithoutRecovery and recoveryWindowInDays are OPTIONAL. Absent means the caller
      # omitted them, which means the 30-day default — not "false was sent".
      | (if ($r.forceDeleteWithoutRecovery == true) then "PERMANENT"
         elif ($r.recoveryWindowInDays != null) then "window=\($r.recoveryWindowInDays)d"
         else "window=30d(default)" end) as $mode
      | "\(.eventTime)  \(.eventName)  " +
        "result=\(if .errorCode then .errorCode else "SUCCESS" end)  " +
        "\(if .eventName == "DeleteSecret" then $mode else "-" end)  " +
        "secret=\($r.secretId // "-")  by=\(.userIdentity.arn)"'
done | sort
```

A `PERMANENT` line is the P0 and no restore exists for it. A `GetSecretValue` line for the same
secret from the same principal shortly before is disclosure followed by destruction.

#### Query 2 — What is scheduled right now, and how long is left

```bash
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secrets --include-planned-deletion --region "$REGION" --output json 2>/dev/null \
| jq -r '.SecretList[] | select(.DeletedDate != null)
    | "\(.Name)",
      "    scheduled:    \(.DeletedDate)",
      "    rotation was: \(if .RotationEnabled then "enabled" else "disabled" end)",
      "    lastAccessed: \(.LastAccessedDate // "never")"'

cat <<'NOTE'

[!] --include-planned-deletion is REQUIRED. Without it, list-secrets omits secrets pending deletion
    entirely, and an inventory taken without the flag will look clean while consumers fail.
[!] Anything listed here is ALREADY unavailable. GetSecretValue fails for a secret scheduled for
    deletion from the moment the call succeeded — the remaining days are for recovering the value,
    not for keeping the service up.
NOTE
```

#### Query 3 — Who consumes the deleted secrets

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"
SECRET="${1:?secret name or ARN from Query 1}"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg s "$SECRET" '[.Events[].CloudTrailEvent | fromjson
    | select((.requestParameters.secretId // "") | contains($s))
    | .userIdentity.arn] | group_by(.)
  | map("  \(length)x  \(.[0])") | .[]'

echo
echo "[!] These are the workloads that are already failing. Every one of them will keep failing until"
echo "    the secret is restored or repointed. Read this list before deciding whether to restore —"
echo "    it is the outage scope, and it is faster than waiting for the pages."
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

`ListSecrets` before the deletions is enumeration, and it means the actor chose these secrets rather
than deleting what they happened to know about — see `../secretsmanager.discovery.secrets-enumerated/`.
`CancelRotateSecret` in the same window is the opposite intent: preserving a value rather than
destroying it, and it is
`../secretsmanager.persistence.secret-value-replaced/`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore first. It is one call, it is reversible in itself, and it is the only step here with a
deadline.

**Break-glass — use the break-glass credential, not the on-call's own.** If the deletion was
`ForceDeleteWithoutRecovery`, there is nothing to restore and the incident becomes a rebuild:
identify the consumers with Query 3, mint replacement credentials at the upstream system, and create
the secret again. Do not spend the first fifteen minutes investigating a secret that cannot come
back.

#### Step 1 — Restore what can be restored

```bash
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secrets --include-planned-deletion --region "$REGION" \
  --query 'SecretList[?DeletedDate!=null].Name' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r N; do
    [ -z "$N" ] && continue
    read -r -p "Restore $N? [y/N] " ANS
    [ "$ANS" = "y" ] || continue
    aws secretsmanager restore-secret --secret-id "$N" --region "$REGION" >/dev/null 2>&1 \
      && echo "[OK] $N restored — consumers recover immediately" \
      || echo "[FAIL] $N could not be restored; it may have been force-deleted"
  done
```

`RestoreSecret` clears the `DeletionDate` and brings the rotation configuration and resource policy
back with it. Restoring a secret that turns out to have been a legitimate decommission costs nothing;
missing the window costs the value.

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

#### Step 3 — Treat every deleted secret's value as disclosed

A principal that could delete a secret could almost always read it first, and Query 1 shows whether
it did. Where it did — or where the permissions make it possible and the log is inconclusive — the
credential inside must be rotated at the **upstream system**: the database password changed at the
database, the API key revoked at the provider. Restoring the Secrets Manager entry restores the
storage, not the secrecy.

#### Step 4 — Check the replicas

```bash
REGION="${AWS_REGION:-us-east-1}"
SECRET="${1:?secret name}"

aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" --output json 2>/dev/null \
| jq -r 'if (.ReplicationStatus // []) | length == 0 then "  no replicas"
         else (.ReplicationStatus[] | "  \(.Region)  \(.Status)  \(.StatusMessage // "")") end'

echo "[!] Replicas are deleted IMMEDIATELY — there is no recovery window for a replica, whatever the"
echo "    primary's window says. If a region's replica is gone, consumers in that region do not"
echo "    recover when the primary is restored; the replica has to be recreated."
```

---

## 4. Eradication

### Remove Attacker Access

#### Separate `DeleteSecret` from `ForceDeleteWithoutRecovery`

IAM cannot condition on the parameter directly, so the practical control is that almost nobody needs
`secretsmanager:DeleteSecret` at all. Applications read secrets; pipelines create and rotate them;
deletion is a decommissioning act performed by a small set of principals under a change record.

#### Deny deletion outside the decommissioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenySecretDeletionOutsideDecommissioning",
  "Effect": "Deny",
  "Action": ["secretsmanager:DeleteSecret"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourDecommissioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone, which here means nobody can ever remove a secret. Test in a non-production OU first.

#### Keep a copy of what deletion takes with it

Rotation configuration and resource policies live only on the secret. Exporting them into the same
repository that defines the secrets is what turns a force-deletion from a reconstruction exercise
into a redeploy.

#### Alarm on the consumer side, not only the API

A secret scheduled for deletion produces `ResourceNotFoundException` in every consumer. That alarm
fires whether or not the deletion rule was deployed, whether or not the event name was cased
correctly, and whether or not the principal was excluded — and in this source set it would have been
the only working signal.

---

## 5. Recovery

### Restore Clean State

#### Verify nothing is still pending deletion

```bash
REGION="${AWS_REGION:-us-east-1}"

N="$(aws secretsmanager list-secrets --include-planned-deletion --region "$REGION" \
      --query 'length(SecretList[?DeletedDate!=null])' --output text 2>/dev/null)"
if [ "${N:-0}" = "0" ]; then
  echo "[OK] no secrets pending deletion in $REGION"
else
  echo "[FAIL] $N secret(s) still pending deletion:"
  aws secretsmanager list-secrets --include-planned-deletion --region "$REGION" \
    --query 'SecretList[?DeletedDate!=null].[Name,DeletedDate]' --output text 2>/dev/null | sed 's/^/  /'
fi
```

#### Verify restored secrets are complete

```bash
REGION="${AWS_REGION:-us-east-1}"
SECRET="${1:?secret name}"

aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" --output json 2>/dev/null \
| jq -r '"  deletionDate:    \(.DeletedDate // "none — restored")",
         "  rotationEnabled: \(.RotationEnabled // false)",
         "  rotationLambda:  \(.RotationLambdaARN // "none")",
         "  versions:        \([.VersionIdsToStages | to_entries[] | .value[]] | join(", "))"'

POL="$(aws secretsmanager get-resource-policy --secret-id "$SECRET" --region "$REGION" \
        --query 'ResourcePolicy' --output text 2>/dev/null)"
echo "  resourcePolicy:  ${POL:-none}"

echo "[!] AWSCURRENT must be present in the versions line. A restored secret without it has no"
echo "    retrievable value, and consumers keep failing even though the secret exists again."
```

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"
NAME="detection-test-$$"

# Create a throwaway secret, schedule it with the MINIMUM window, then restore it. This exercises the
# seven-day rule without ever exercising the permanent one — force-deletion is not something to test
# against a real account.
aws secretsmanager create-secret --name "$NAME" --secret-string "test" --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] created $NAME"

aws secretsmanager delete-secret --secret-id "$NAME" --recovery-window-in-days 7 --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] scheduled with the 7-day minimum — expect the minimum-window alert, NOT a generic one"

sleep 30
aws secretsmanager restore-secret --secret-id "$NAME" --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] restored"
aws secretsmanager delete-secret --secret-id "$NAME" --force-delete-without-recovery --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] test secret removed permanently — this SHOULD also raise the critical alert"
```

The last line is deliberate: it is the one safe force-deletion, and it doubles as the test for the
critical rule.

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was `ForceDeleteWithoutRecovery` used? | It is the whole triage. One outcome is a single restore call; the other is a rebuild. |
| Did the same principal read the value first? | Disclosure followed by destruction is a larger incident than either half. |
| Which workloads consume the deleted secrets? | They are already failing, and the consumer list is the outage scope. |
| Were replicas involved? | Replicas delete immediately with no window, and restoring the primary does not bring them back. |
| Was the window set to the seven-day minimum? | Routine decommissioning takes the default; the floor is a deliberate choice to shorten your time. |
| How did the principal hold `secretsmanager:DeleteSecret`? | Applications read secrets and pipelines rotate them; almost nothing needs to delete one. |

### Recommended Guardrails

**Read the request body.** Reversible and permanent deletion are different incidents and the
parameter that separates them is in the event.

**Never write `NOT forceDeleteWithoutRecovery:"false"`.** The parameter is absent when omitted, so
that form matches every ordinary deletion.

**Restore before investigating.** The investigation does not expire; the recovery window does.

**Alarm on `ResourceNotFoundException` in consumers.** It is independent of the detection rule and it
would have been the only working signal in this source set.

**Keep rotation configuration and resource policies in source control.** They are deleted with the
secret and they are what makes a force-deletion expensive.

### Technique Reference

**T1485 — Data Destruction.** Verified live at https://attack.mitre.org/techniques/T1485/ on
2026-08-30. Destroying stored credential material is what this technique names.

**T1489 — Service Stop.** Verified live 2026-08-30. It covers the immediate half: consumers stop
working the moment the secret is scheduled, not when it is finally destroyed.

The source rule maps `T1528 — Steal Application Access Token` under Credential Access. Deleting a
secret steals nothing — and where the value *was* read first, the disclosure is `T1555.006` and is
owned by the neighbouring retrieval playbook.

AWS references relied on throughout, all verified 2026-08-30:

- `DeleteSecret` API reference — the recovery-window semantics, `ForceDeleteWithoutRecovery`, the
  statement that a scheduled secret cannot be retrieved, and immediate replica deletion:
  https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
- Secrets Manager CloudTrail logging — all API calls recorded as management events:
  https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html

Service-wide verified behaviour shared by every `secretsmanager.*` playbook is in
`../_ground-truth/secretsmanager.md`.

### Residual Risk

**A force-deleted secret cannot be recovered from anywhere.** CloudTrail never recorded the value, so
the log does not help. The only recovery is minting new credentials upstream.

**`list-secrets` hides pending deletions by default.** Without `--include-planned-deletion` an
inventory looks clean while consumers fail, which is a plausible way to miss this entirely.

**Replicas have no window.** Restoring the primary does not restore a deleted replica, and consumers
in that region stay broken until it is recreated.

**A restored secret can come back without `AWSCURRENT`.** The secret exists, `describe-secret`
succeeds, and `GetSecretValue` still fails — which reads like a restore that did not work rather than
a staging-label problem.
