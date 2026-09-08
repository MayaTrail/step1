# IR Playbook: Secrets Manager Access Repeatedly Denied — `AccessDenied` bursts and what separates a loop from a probe

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Discovery — a principal is repeatedly refused by Secrets Manager while establishing what it can reach |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when a denial burst accompanies a successful retrieval; high for denials across five or more distinct secrets, or ten from one session; medium for repeated denials against a single secret, which is the retry-loop shape. The source rule is P4. |
| MITRE Tactics | Discovery |
| MITRE Techniques | T1526 |
| Services in Scope | Secrets Manager, IAM, CloudTrail |

**What the technique does:** the actor establishes what its credential can reach. Every refusal is a
data point, and the refusals are free — Secrets Manager records them all as management events.

**Why the usual reflexes miss it.** The first is the MITRE mapping: this is called brute force under
Initial Access, when the credential already authenticated and only the authorization failed. The
second is the grouping key — the role name, which cannot tell one session from twenty. The third is
the threshold, twenty in five minutes, which selects for a retry loop. The fourth is the missing
dimension: nothing in the rule separates one secret refused twenty times from twenty secrets refused
once, and that is the whole triage.

**Detection thesis:** group on the session, lower the threshold, widen the error match, and add the
per-secret cardinality that turns a noisy counter into a usable signal.

**Adjacent playbooks.** Successful listing of the inventory is
`../secretsmanager.discovery.secrets-enumerated/`. Retrieval volume is
`../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`. A resource
policy opened on a secret is
`../secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. AWS records **all** Secrets Manager API calls, denials
included, so the data here is complete and free — see `../_ground-truth/secretsmanager.md` §1.

**A record of which error codes your account actually produces.** SCPs and permissions boundaries
surface as `AccessDeniedException` rather than `AccessDenied`, so a rule written against the exact
string under-counts in exactly the accounts that invest most in guardrails.

**A baseline of expected denial volume per role.** Least-privilege environments produce a steady
background; without knowing yours, every threshold is a guess.

**Alerting (must be pre-configured)**

- **A denial burst from a session that also completed a successful `GetSecretValue` → P0**
- **Denials against five or more distinct secrets from one session in fifteen minutes → P1**
- **Ten or more Secrets Manager denials from one session in fifteen minutes → P1**

**Response Tooling**

An IAM principal that can call `iam simulate-principal-policy`,
`secretsmanager get-resource-policy` and `secretsmanager describe-secret` outside the change
pipeline. `describe-secret` returns metadata only and never a value, so it is safe to run broadly
during an incident.

**Known IOC Baselines**

The roles whose workloads legitimately probe — deployment tooling that iterates a list of secrets it
may not yet be granted. These are the dominant false positive and they are enumerable.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | A denial burst from a session that also completed a successful `GetSecretValue` or `BatchGetSecretValue` | CloudTrail | T1526 |
| P1 | Denials against five or more distinct secret identifiers from one session within fifteen minutes | Correlation rule | T1526 |
| P1 | Ten or more Secrets Manager denials from one session within fifteen minutes | Correlation rule | T1526 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | Ten or more denials against a **single** secret identifier — the retry-loop shape | CloudTrail | T1526 |
| P2 | Denials carrying `AccessDeniedException` rather than `AccessDenied` — an SCP or boundary the source filter drops | CloudTrail | T1526 |
| P3 | An isolated denial from a principal with no history of Secrets Manager use | CloudTrail | T1526 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `T1110 — Brute Force` under Initial Access | Brute force is guessing credentials. `AccessDenied` goes to a principal whose credential authenticated and whose authorization failed. Initial Access is wrong for the same reason — the actor is inside | `T1526 — Cloud Service Discovery` |
| Grouped by `sessionIssuer.userName` — the **role** name | Every concurrent session shares it. Twenty sessions with one denial each look identical to one session with twenty, and the alert names the role rather than the actor | Grouped on `userIdentity.arn`, which carries the session |
| Twenty denials in five minutes | Four a minute sustained is a workload retrying in a loop, not a person | Ten in fifteen minutes — still catches the loop, also catches a patient actor |
| `errorCode:"AccessDenied"` exactly | An SCP or permissions-boundary denial can surface as `AccessDeniedException`, so the filter under-counts in accounts that use them | Prefix match, plus `UnauthorizedOperation` |
| No per-secret cardinality | One secret refused twenty times and twenty secrets refused once are the same alert, and they are different incidents | A second correlation on distinct `secretId` |
| Rated P4 | A denial burst alongside a successful retrieval is the shape that matters and it is rated the same as background noise | Severity driven by cardinality and by whether anything succeeded |

**Recommended detection — grouped on the session, with the cardinality that does the triage.**

```yaml
# Secrets Manager access repeatedly denied (T1526)
#
# THE RULE IS MAPPED TO BRUTE FORCE UNDER INITIAL ACCESS. Brute force is guessing credentials. An
# AccessDenied from Secrets Manager goes to a principal whose credential already AUTHENTICATED and
# whose AUTHORIZATION failed — the actor is already inside, and this is discovery.
#
# IT GROUPS BY `sessionIssuer.userName`, WHICH IS THE ROLE NAME. Every concurrent session of a role
# shares it, so twenty sessions with one denial each look identical to one session with twenty, and
# the alert names the role instead of the actor. Regrouped on the session below. See
# ../../_ground-truth/secretsmanager.md §8.
#
# ITS THRESHOLD IS TWENTY IN FIVE MINUTES — four a minute sustained, which is a workload retrying in
# a loop rather than a person. Ten in fifteen minutes catches both.
#
# AND IT MATCHES `AccessDenied` EXACTLY. A call blocked by an SCP or a permissions boundary can
# surface with a different code, so the exact filter under-counts wherever those are used.
#
# Every Secrets Manager call is a management event, so these documents work without data events.
# Successful listing is a different use case: ../../secretsmanager.discovery.secrets-enumerated/.
name: secretsmanager_call_denied
title: Secrets Manager call denied
id: f8d26c25-d03a-4f9f-8d5c-f8da58011abd
status: experimental
description: >-
  Any Secrets Manager API call returning an authorization failure. Base rule — informational alone,
  because least-privilege accounts produce a steady background of these. Not brute force: the
  principal's credential authenticated and its authorization failed.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  # Both keys are on the SAME event: CloudTrail writes eventSource and errorCode into one record, so
  # a denied Secrets Manager call carries both. ANDing them is correct.
  #
  # `startswith` rather than an exact match: an SCP or permissions-boundary denial can surface as
  # AccessDeniedException rather than AccessDenied, and an exact filter silently drops those.
  selection:
    eventSource: secretsmanager.amazonaws.com
    errorCode|startswith: AccessDenied
  selection_unauth:
    eventSource: secretsmanager.amazonaws.com
    errorCode: UnauthorizedOperation
  filter_automation:
    userIdentity.arn|contains: 'PlatformAutomation'
  condition: (selection or selection_unauth) and not filter_automation
falsepositives:
  - Least-privilege environments produce a steady background of these
  - Cross-account access that has not been granted on the secret's resource policy
level: informational
---
# Ten in fifteen minutes, grouped on the SESSION rather than the role. The source uses twenty in
# five, grouped on a field that collapses every session of a role into one counter.
title: Secrets Manager denials repeated by one session
id: 9043d25b-a5ee-47b1-9fca-279d4a3002f5
status: experimental
description: >-
  One session was denied ten or more times by Secrets Manager within fifteen minutes. Grouped on the
  session ARN so that concurrent sessions of a shared role are counted separately, which the source
  rule's role-name grouping cannot do.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
correlation:
  type: event_count
  rules:
    - secretsmanager_call_denied
  group-by:
    - userIdentity.arn
  timespan: 15m
  condition:
    gte: 10
falsepositives:
  - A misconfigured workload retrying a denied call in a tight loop — check whether the target secret
    is a single ARN repeated, which is the signature of a loop rather than of probing
level: high
---
# The distinction the source rule cannot express: many DISTINCT secrets denied is an inventory being
# probed; one secret repeated is a workload missing a grant. This is the discriminating document.
title: Secrets Manager denials spread across many distinct secrets
id: bad541d1-fda2-4ba0-b54d-d7f260039f9b
status: experimental
description: >-
  One session was denied against five or more distinct secret identifiers within fifteen minutes.
  Unlike a retry loop, which repeats one identifier, this is a principal walking the inventory to
  find what it can reach.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
correlation:
  type: value_count
  rules:
    - secretsmanager_call_denied
  group-by:
    - userIdentity.arn
  timespan: 15m
  condition:
    gte: 5
    field: requestParameters.secretId
falsepositives:
  - A newly deployed workload iterating over a list of secrets it has not been granted yet, which
    resolves once and should then be allowlisted by role
level: high
```

What this set structurally cannot do: see the actor who has the permissions. A principal that is
never refused produces no denial at all, and this playbook is blind to it by construction — that case
belongs to `../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> Secrets Manager is **regional**. Every call is a management event, so an empty result here
> genuinely means it did not happen.

Run Query 1 first; it answers whether this is a loop or a probe, and whether anything succeeded.

#### Query 1 — Reconstruct: loop or probe, and did anything succeed

```bash
PRINCIPAL="${1:?principal ARN from the alert}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in GetSecretValue BatchGetSecretValue DescribeSecret ListSecrets PutSecretValue; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg p "$PRINCIPAL" '.Events[].CloudTrailEvent | fromjson
      | select(.userIdentity.arn == $p)
      | "\(.eventTime)  \(.eventName)  " +
        "result=\(if .errorCode then .errorCode else "SUCCESS" end)  " +
        "secret=\(.requestParameters.secretId // "-")  ip=\(.sourceIPAddress)"'
done | sort > /tmp/sm-denials-$$.txt

cat /tmp/sm-denials-$$.txt
echo
echo "=== distinct secrets denied ==="
grep -v 'result=SUCCESS' /tmp/sm-denials-$$.txt | sed 's/.*secret=//' | awk '{print $1}' | sort | uniq -c | sort -rn
echo
echo "=== anything that SUCCEEDED ==="
grep 'result=SUCCESS' /tmp/sm-denials-$$.txt || echo "  (nothing succeeded)"
rm -f /tmp/sm-denials-$$.txt
```

**One secret id repeated** is a workload missing a grant — the dominant explanation, and it resolves
with an IAM change rather than an incident. **Many distinct ids** is the inventory being probed. A
`SUCCESS` line on `GetSecretValue` changes the incident class entirely: something was reachable, and
that secret must be treated as disclosed.

#### Query 2 — What error codes are actually being returned

```bash
PRINCIPAL="${1:?principal ARN}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r '[.Events[].CloudTrailEvent | fromjson
    | select(.eventSource == "secretsmanager.amazonaws.com")
    | select(.errorCode != null) | .errorCode] | group_by(.)
  | map("  \(length)x  \(.[0])") | .[]'

cat <<'NOTE'

[!] If anything other than plain `AccessDenied` appears — AccessDeniedException, or an SCP-shaped
    message — the source rule's exact-match filter was dropping those events entirely. That is the
    likeliest reason a burst you can see in the log never raised an alert.
NOTE
```

#### Query 3 — What would have succeeded, and what the resource policies allow

```bash
PRINCIPAL="${1:?principal ARN}"
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secrets --region "$REGION" --query 'SecretList[].ARN' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r ARN; do
    [ -z "$ARN" ] && continue
    DEC="$(aws iam simulate-principal-policy --policy-source-arn "$PRINCIPAL" \
            --action-names secretsmanager:GetSecretValue --resource-arns "$ARN" \
            --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null)"
    case "$DEC" in
      allowed) echo "[!] ALLOWED  $ARN" ;;
      "")      echo "[?] unknown  $ARN — simulate-principal-policy did not evaluate" ;;
      *)       echo "[OK] $DEC  $ARN" ;;
    esac
  done

echo
echo "[!] simulate-principal-policy does NOT evaluate a secret's RESOURCE policy for a cross-account"
echo "    principal, so an 'ALLOWED' list built this way is a floor rather than a ceiling. Pair it"
echo "    with get-resource-policy on anything the probing touched."
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

Denials against **other** services in the same window — `s3`, `ssm`, `kms`, `iam` — turn this from a
Secrets Manager finding into account mapping, and the response widens accordingly. A principal being
refused everywhere is establishing a permission boundary, which is what an actor does with a
credential it did not provision.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Establish which of the two shapes you have before doing anything else. A retry loop needs a ticket; a
probe needs containment, and treating one as the other wastes the window either way.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows any
`SUCCESS` on `GetSecretValue`, the credential inside that secret is disclosed. Go to
`../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/` and rotate
it at the upstream system; the denials are then context rather than the incident.

#### Step 1 — Decide: loop or probe

```bash
PRINCIPAL="${1:?principal ARN}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-1d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '1 day ago' '+%Y-%m-%dT%H:%M:%SZ')"

N="$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg p "$PRINCIPAL" '[.Events[].CloudTrailEvent | fromjson
    | select(.userIdentity.arn == $p) | select(.errorCode != null)
    | .requestParameters.secretId // "-"] | unique | length')"

echo "distinct secrets denied in the last 24h: ${N:-unknown}"
if [ "${N:-0}" -le 1 ]; then
  echo "[!] RETRY LOOP shape — one identifier. This is very likely a workload missing a grant."
  echo "    Do not contain the principal on this alone; identify the workload and fix the policy."
elif [ "${N:-0}" -ge 5 ]; then
  echo "[FAIL] PROBE shape — ${N} distinct identifiers. Continue to Step 2."
else
  echo "[?] INCONCLUSIVE — ${N} identifiers. Read Query 1's output before containing anything."
fi
```

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

#### Step 3 — Establish how the credential was obtained

A principal probing Secrets Manager already has valid credentials. The question this playbook cannot
answer, and that decides the real scope, is where they came from — a leaked access key, an assumed
role reached through a permissive trust policy, or a compromised workload. Query 4's cross-service
denials are the fastest indicator: a principal refused across several services at once is one whose
holder does not know what it is for.

#### Step 4 — Close whatever it did reach

Query 3's `ALLOWED` list is what the credential could have read and may still be able to. Where that
list is not empty and the principal is not contained, those secrets are exposed regardless of the
denials — the denials only tell you what it could not reach.

---

## 4. Eradication

### Remove Attacker Access

#### Match the error code by prefix, not by string

`AccessDeniedException` is not `AccessDenied`, and an SCP-based denial can produce either. A rule
written against the exact string under-counts most in the accounts that have invested most in
guardrails, which is the wrong way round.

#### Group thresholds on the session

`sessionIssuer.userName` is the role name and it is shared by every concurrent session. Any threshold
grouped on it counts a fleet as one actor and one actor as a fleet.

#### Add cardinality to every threshold rule that names a resource

A count answers "how much"; the distinct-resource count answers "what kind". For this technique the
second question is the whole triage, and it is one extra field.

#### Deny cross-service enumeration outside the operator path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenySecretsManagerEnumerationOutsideOperators",
  "Effect": "Deny",
  "Action": ["secretsmanager:ListSecrets", "secretsmanager:DescribeSecret"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourOperatorRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone. Note the second-order effect specific to this playbook: an SCP denial changes the error
code the principal receives, so deploying this **and** leaving an exact-match `AccessDenied` rule in
place produces a guardrail whose activity is invisible. Deploy the prefix-matching rule first. Test
in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify the contained principal can no longer reach any secret

```bash
PRINCIPAL="${1:?principal ARN}"
REGION="${AWS_REGION:-us-east-1}"
FAIL=0

for ARN in $(aws secretsmanager list-secrets --region "$REGION" --query 'SecretList[].ARN' --output text 2>/dev/null); do
  DEC="$(aws iam simulate-principal-policy --policy-source-arn "$PRINCIPAL" \
          --action-names secretsmanager:GetSecretValue --resource-arns "$ARN" \
          --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null)"
  if [ -z "$DEC" ]; then
    echo "[?] $ARN — simulate-principal-policy returned nothing; INCONCLUSIVE, check manually"; FAIL=1
  elif [ "$DEC" = "allowed" ]; then
    echo "[FAIL] $ARN — still reachable"; FAIL=1
  fi
done
[ "$FAIL" -eq 0 ] && echo "[OK] no secret is reachable by $PRINCIPAL"
```

The `INCONCLUSIVE` branch is deliberate: an empty result from the simulator is not a pass, and
collapsing it into one is how a recovery check reports success without having checked anything.

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"

# Run as a principal WITHOUT secretsmanager permissions — an unprivileged test role, not your own
# session. Ten calls against TEN DIFFERENT names exercises the cardinality correlation, which is the
# document the source rule has no equivalent for.
for i in 1 2 3 4 5 6 7 8 9 10; do
  aws secretsmanager get-secret-value --secret-id "detection-test-$$-$i" --region "$REGION" \
    >/dev/null 2>&1 && echo "[!] call $i SUCCEEDED — rerun as an unprivileged principal"
done
echo "[OK] ten denials against ten distinct identifiers issued"
echo "[!] Expect BOTH correlations: the count rule and the distinct-secrets rule. If only the count"
echo "    rule fires, the cardinality document is not deployed and a retry loop will look identical"
echo "    to a probe."
```

Note that these identifiers do not exist, so the error may be `ResourceNotFoundException` rather than
an authorization failure where the principal *does* hold a wildcard grant — read the codes Query 2
reports before concluding the rule is broken.

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| One secret repeated, or many distinct? | It is the entire triage: a retry loop is a ticket, a probe is an incident. |
| Did anything succeed? | A denial burst alongside a successful retrieval is disclosure, not reconnaissance. |
| What error codes were returned? | An SCP denial surfaces as `AccessDeniedException`, which the source filter drops entirely. |
| Was the principal refused by other services too? | A credential refused everywhere is one whose holder does not know what it is for. |
| What could the principal have reached? | The denials say what it could not; the exposure is what it could. |
| Which session, not which role? | The role-name grouping names the wrong thing in the alert and merges unrelated actors. |

### Recommended Guardrails

**Match error codes by prefix.** `AccessDeniedException` is not `AccessDenied`, and the exact-match
form fails hardest in the best-governed accounts.

**Group on the session ARN.** The role name is shared by every concurrent session.

**Add distinct-resource cardinality to resource-scoped threshold rules.** It converts a noisy counter
into a triage decision at the cost of one field.

**Deploy the prefix-matching rule before any new SCP.** An SCP changes the error code, so the
guardrail's own activity becomes invisible to a rule written against the old one.

**Expect this alert to be benign.** Saying so in the finding is what keeps it from being ignored on
the day it is not.

### Technique Reference

**T1526 — Cloud Service Discovery.** Verified live at https://attack.mitre.org/techniques/T1526/ on
2026-08-31. Establishing which cloud resources a credential can reach is what this technique names.

The source rule maps `T1110 — Brute Force` under Initial Access. Brute force is guessing credentials;
an `AccessDenied` from Secrets Manager is an authorization failure returned to a principal whose
credential already authenticated, and Initial Access is wrong for the same reason — the actor is
already inside. `T1580 — Cloud Infrastructure Discovery` was considered and set aside: it is scoped
to IaaS compute and storage resources.

AWS references relied on throughout, all verified 2026-08-30:

- Secrets Manager CloudTrail logging — the statement that **all** API calls are recorded as
  management events, denials included:
  https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html
- `GetSecretValue` API reference — the call whose refusal makes up most of a denial burst:
  https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html

Service-wide verified behaviour shared by every `secretsmanager.*` playbook is in
`../_ground-truth/secretsmanager.md`.

### Residual Risk

**An actor with the permissions produces no denial at all.** This playbook is blind to the case where
the credential is correctly scoped for what the actor wants, and that is the more dangerous case.

**Denials are cheap and constant.** Least-privilege environments generate a background that makes any
absolute threshold arbitrary; the cardinality field is what carries the signal, not the count.

**`simulate-principal-policy` does not evaluate resource policies for cross-account principals.** The
"what could they reach" list is a floor, not a ceiling.

**A non-existent secret returns `ResourceNotFoundException`, not a denial, for a principal holding a
wildcard grant.** So an actor probing names it cannot guess may look like it is being refused when it
is actually being told the secret does not exist — which is itself information, and neither rule
here reports it.
