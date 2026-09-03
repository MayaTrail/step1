# IR Playbook: Secrets Manager Inventory Enumerated — `ListSecrets`, and the path around it

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Discovery — a principal reads the account's secret inventory, either by listing it or by describing it one ARN at a time |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical if any `GetSecretValue` succeeded; high when the inventory is walked via `DescribeSecret` without ever calling `ListSecrets`; medium for listing by a principal outside the consumer allowlist, or a refused listing. The source rule is P3. |
| MITRE Tactics | Discovery |
| MITRE Techniques | T1526 (primary); T1555.006 (the objective the enumeration serves) |
| Services in Scope | Secrets Manager, IAM, CloudTrail |

**What the technique does:** the actor reads the inventory before choosing a target. `ListSecrets`
returns no secret values — it returns `Name`, `Description`, `Tags`, `RotationEnabled`,
`LastAccessedDate` and `LastRotatedDate`. That is which systems exist, which secrets are live, and
which will never rotate.

**Why the usual reflexes miss it.** The first is treating listing as harmless because no value came
back. The second is the building block's error filter: a **refused** listing is not a listing event,
so a principal that asked for everything and was told no produces nothing. The third is scoping the
detection to `ListSecrets` at all — a principal with ARNs but no list permission enumerates with
`DescribeSecret` and returns the same metadata, one call at a time.

**Detection thesis:** report a refused listing with no threshold, cover the `DescribeSecret` path the
source set has no rule for, and let one question — did any retrieval succeed — set the severity.

**Adjacent playbooks.** Denial bursts across the service are
`../secretsmanager.discovery.access-repeatedly-denied/`. Retrieval volume and the list-then-retrieve
sequence are
`../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`. A resource
policy opened on a secret is
`../secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. Nothing else is needed: AWS records **all** Secrets
Manager API calls as management events, so `GetSecretValue` is captured by default and there are no
data events to purchase — see `../_ground-truth/secretsmanager.md` §1.

Retention long enough to answer "has this principal ever listed before". The source's new-value rule
depends on a baseline, and a 90-day trail gives a weak one.

**Alerting (must be pre-configured)**

- **Any successful `GetSecretValue` by a principal that also enumerated → P0**
- **`DescribeSecret` across ten or more distinct secrets by one session with no `ListSecrets` → P1**
- **`ListSecrets` returning an authorization failure — no threshold → P2**
- **`ListSecrets` succeeding for a principal outside the consumer allowlist → P2**

**Response Tooling**

An IAM principal that can call `secretsmanager list-secrets`, `secretsmanager describe-secret` and
`iam simulate-principal-policy` outside the change pipeline. `describe-secret` returns metadata only
and never the value, so it is safe to run broadly during an incident.

**Known IOC Baselines**

The roles that legitimately consume secrets, populating `known_consumers`. Without it the listing
rule reports every SDK credential provider and every console session.

The secrets whose disclosure would be an incident on its own, tagged. Enumeration is only as serious
as what it found, and that judgement should not be made under time pressure.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | A principal that enumerated then called `GetSecretValue` or `BatchGetSecretValue` successfully | CloudTrail | T1555.006 |
| P1 | `DescribeSecret` across ten or more distinct secrets by one session, with no `ListSecrets` at all | Correlation rule | T1526 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `ListSecrets` returning an authorization failure — invisible to the source building block | CloudTrail | T1526 |
| P2 | `ListSecrets` succeeding for a principal outside the consumer allowlist | CloudTrail | T1526 |
| P3 | `DescribeSecret` across ten or more distinct secrets by a principal that also lists legitimately | Correlation rule | T1526 |

### Detection Rule Quality Notes

The source is a new-value rule over one threshold building block, both fully readable, so every row
below is auditable against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Building block ends `NOT _exists_:errorCode` | A **denied** `ListSecrets` is not a listing event, so a principal that asked for the whole inventory and was refused leaves no trace | A denied-listing rule with **no threshold** |
| Scoped to `ListSecrets` only | A principal with ARNs but no list permission enumerates with `DescribeSecret`, returning the same metadata one call at a time. Nothing in the source set sees it | A `value_count` correlation on distinct `secretId` over `DescribeSecret` |
| `T1552 — Unsecured Credentials` | Secrets Manager is a credential store used as designed. Nothing about it is unsecured | `T1526` for the enumeration, `T1555.006` for the objective |
| Listing rated as low-value because no secret is returned | The response carries names, tags, rotation state and last-accessed dates — the reconnaissance product | Rated, with what it discloses stated in §2 Query 2 |
| No principal dimension on the building block | Console sessions and SDK credential providers call `ListSecrets` constantly | `known_consumers` allowlist |
| The new-value rule has no query of its own | It is a correlation over the building block, which is why the two are one use case rather than two | Kept together; the merge case is recorded in `_source/PROVENANCE.md` |

**Recommended detection — both enumeration paths, and the refusal the source cannot see.**

```yaml
# Secrets Manager inventory enumerated (T1526)
#
# TWO SOURCE RULES, AND THE GAP BETWEEN THEM IS WHERE A CAREFUL ACTOR SITS. The listing building
# block excludes errors (`NOT _exists_:errorCode`), so a DENIED ListSecrets is not a listing event.
# The denial rule needs twenty failures in five minutes. A principal issuing three denied calls a
# minute is invisible to both. `secretsmanager_secrets_listed_denied` below has no threshold and
# closes it.
#
# THE DENIAL RULE IS MAPPED TO BRUTE FORCE UNDER INITIAL ACCESS. Brute force is guessing
# credentials. An AccessDenied from Secrets Manager goes to a principal whose credential already
# worked and whose AUTHORIZATION did not — the actor is already inside, and this is discovery.
#
# IT ALSO GROUPS BY `sessionIssuer.userName`, WHICH IS THE ROLE NAME. Every concurrent session of a
# role shares it, so twenty sessions with one denial each look identical to one session with twenty,
# and the alert names the role instead of the actor. Regrouped on the session below. See
# ../../_ground-truth/secretsmanager.md §8.
#
# LISTING IS NOT HARMLESS BECAUSE NO VALUE IS RETURNED. ListSecrets returns names, descriptions,
# tags, RotationEnabled and LastAccessedDate — which systems exist, which secrets are live, and which
# will never rotate. See ../../_ground-truth/secretsmanager.md §3.
#
# EVERY SECRETS MANAGER CALL IS A MANAGEMENT EVENT. There are no data events to buy, so all four
# documents below work in any account with a trail.
title: Secrets Manager inventory listed by an unexpected principal
id: 146a47ed-a255-4c5f-87f1-f56f36dd89af
status: experimental
description: >-
  A principal outside the known-consumer allowlist called ListSecrets successfully. The response
  carries secret names, descriptions, tags, rotation state and last-accessed dates — the inventory an
  actor uses to choose what to retrieve next. Retrieval itself is owned by
  secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: ListSecrets
    errorCode: null
  filter_known:
    userIdentity.arn|contains:
      - 'SecretsConsumerRole'
      - 'PlatformAutomation'
  condition: selection and not filter_known
falsepositives:
  - Secrets Manager console sessions — opening the Secrets page calls ListSecrets
  - Inventory, backup and compliance tooling that walks every secret on a schedule
  - SDK credential providers that list before selecting
level: medium
---
# The gap-closer. NO THRESHOLD. A single denied ListSecrets is a principal that tried to read the
# inventory and was refused, which is a stronger signal than a successful one from a role that is
# supposed to list. The source pair sees this only at twenty denials in five minutes.
title: Secrets Manager inventory listing denied
id: 79d2a509-689a-4220-94fb-b1312e255026
status: experimental
description: >-
  ListSecrets returned AccessDenied. The source building block excludes errors and the source denial
  rule requires twenty failures in five minutes, so a slow enumerator falls through both. This has no
  threshold.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: ListSecrets
    errorCode: AccessDenied
  # justified: no threshold and no allowlist, deliberately. A refused ListSecrets is a principal that
  # asked for the whole inventory and was told no; there is no volume at which that becomes more or
  # less interesting, and an allowlist would reintroduce the gap this document exists to close. The
  # expected false positive — a workload deployed before its policy grant — is named below and is
  # resolved by reading the target principal once.
  condition: selection
falsepositives:
  - A newly deployed workload whose IAM policy has not been granted secretsmanager:ListSecrets yet
  - A console user without Secrets Manager permissions opening the service page
level: medium
---
name: secretsmanager_secret_described
title: Secrets Manager secret metadata read
id: 6c47d928-07fc-4f38-a5bf-6f5918f1e260
status: experimental
description: >-
  DescribeSecret returns the same metadata as a ListSecrets entry for one secret. A principal holding
  ARNs but not ListSecrets enumerates this way, one call at a time, and nothing in the source set
  sees it. Base rule for the correlation below.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: DescribeSecret
    errorCode: null
  filter_known:
    userIdentity.arn|contains:
      - 'SecretsConsumerRole'
      - 'PlatformAutomation'
  condition: selection and not filter_known
falsepositives:
  - Console sessions, which call DescribeSecret on each secret the user opens
  - SDK credential providers that describe before retrieving
level: informational

---
# The path the source set has no rule for. Ten distinct secrets described in fifteen minutes is an
# inventory being walked one ARN at a time, by a principal that either lacks ListSecrets or is
# avoiding it.
title: Secrets Manager metadata read across many distinct secrets
id: 970ad2e7-6a13-40d2-81a7-79c388247478
status: experimental
description: >-
  One session called DescribeSecret against ten or more distinct secrets within fifteen minutes.
  This returns the same reconnaissance metadata as ListSecrets — names, tags, rotation state,
  last-accessed dates — without ever calling the API the source rules watch.
references:
  - https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
correlation:
  type: value_count
  rules:
    - secretsmanager_secret_described
  group-by:
    - userIdentity.arn
  timespan: 15m
  condition:
    gte: 10
    field: requestParameters.secretId
falsepositives:
  - An inventory or compliance job walking every secret on a schedule, which should be identified by
    role and added to the base rule's allowlist
level: medium
```

What this set structurally cannot do: tell you what the enumeration returned. CloudTrail records the
call and never the response body, so the inventory the actor saw has to be reconstructed from your
side in §2 Query 2 — and it may differ from theirs if permissions changed in between.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> Secrets Manager is **regional**. Every call is a management event, so an empty result here
> genuinely means it did not happen — unlike the S3 and DynamoDB equivalents.

Run Query 1 first; it answers the only question that sets severity.

#### Query 1 — Did enumeration become retrieval, and by which path

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in ListSecrets DescribeSecret GetSecretValue BatchGetSecretValue; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | "\(.eventTime)  \(.eventName)  " +
        "result=\(if .errorCode then .errorCode else "SUCCESS" end)  " +
        "secret=\(.requestParameters.secretId // .requestParameters.secretIdList // "-" | tostring)  " +
        "by=\(.userIdentity.arn)  ip=\(.sourceIPAddress)"'
done | sort
```

A `GetSecretValue` line reading `SUCCESS` from the same principal as the enumeration is the P0.
There is no partial disclosure: CloudTrail does not record the value, so a successful call must be
treated as the credential having been read — see `../_ground-truth/secretsmanager.md` §2.

A run of `DescribeSecret` lines with **no** `ListSecrets` line is the path the source rules do not
watch: the principal has ARNs and is walking them one at a time.

#### Query 2 — Reconstruct the inventory the actor saw

```bash
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secrets --region "$REGION" --output json 2>/dev/null \
| jq -r '.SecretList[]
    | "\(.Name)",
      "    rotation:     \(if .RotationEnabled then "enabled" else "DISABLED — a stolen value stays valid" end)",
      "    lastAccessed: \(.LastAccessedDate // "never")",
      "    lastRotated:  \(.LastRotatedDate // "never rotated")",
      "    tags:         \([.Tags[]? | "\(.Key)=\(.Value)"] | join(", ") // "-")",
      "    description:  \(.Description // "-")"'

cat <<'NOTE'

[!] This is metadata only — list-secrets never returns a value, which is exactly why the actor
    called it. Read the names and tags as the actor would: they name the systems, the environments
    and the owners. Secrets with rotation DISABLED are the ones worth stealing, because the value
    they hold now is the value they will hold indefinitely.
[!] DescribeSecret returns this same block for ONE secret. A principal without ListSecrets sees the
    identical picture, just more slowly and one ARN at a time.
NOTE
```

#### Query 3 — Sweep: who else has enumerated recently

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"
# POPULATE with the roles that legitimately consume secrets.
KNOWN="SecretsConsumerRole PlatformAutomation"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListSecrets \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r '[.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) | .userIdentity.arn]
    | group_by(.) | map({arn: .[0], n: length}) | sort_by(-.n) | .[]
    | "\(.n)\t\(.arn)"' \
| while IFS="$(printf '\t')" read -r N ARN; do
    [ -z "$ARN" ] && continue
    MATCH=0
    for K in $KNOWN; do case "$ARN" in *"$K"*) MATCH=1 ;; esac; done
    [ "$MATCH" -eq 1 ] && echo "[OK] ${N}x  $ARN" || echo "[!] ${N}x  $ARN — outside the consumer allowlist"
  done
```

Enumeration by one principal is a finding; enumeration by several unrelated principals in the same
window is usually a new tool or a new pipeline, and the sweep tells you which before you contain
anyone.

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

Enumeration rarely stops at one service. `ListBuckets`, `ListFunctions`, `DescribeInstances`,
`GetCallerIdentity` and `ListRoles` around the same window are the same activity against everything
else, and they change the incident from "someone read the secret inventory" to "someone is mapping
the account". A burst of refusals alongside them is
`../secretsmanager.discovery.access-repeatedly-denied/`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Enumeration alone is not urgent. Retrieval is. Query 1 decides which of the two you are in, and it
takes under a minute.

**Break-glass — use the break-glass credential, not the on-call's own.** If any `GetSecretValue`
succeeded, the credential inside that secret must be treated as disclosed. Go to
`../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/` for the
disclosure response and rotate there; this playbook's job is finished once you know which secrets
were read.

#### Step 1 — Contain the principal

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

#### Step 2 — Establish what the principal was actually allowed to read

```bash
PRINCIPAL="${1:?principal ARN}"
REGION="${AWS_REGION:-us-east-1}"

echo "[!] The enumeration tells you what it saw. This tells you what would have SUCCEEDED — which is"
echo "    the exposure if the session is still live."

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
```

`simulate-principal-policy` does not evaluate a secret's **resource policy** for a cross-account
principal, so an `allowed` list built this way is a floor rather than a ceiling. Pair it with Step 3.

#### Step 3 — Check for a resource policy that widens the exposure

```bash
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secrets --region "$REGION" --query 'SecretList[].Name' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r N; do
    [ -z "$N" ] && continue
    POL="$(aws secretsmanager get-resource-policy --secret-id "$N" --region "$REGION" \
            --query 'ResourcePolicy' --output text 2>/dev/null)"
    [ -z "$POL" ] || [ "$POL" = "None" ] && continue
    if printf '%s' "$POL" | grep -q '"AWS"[[:space:]]*:[[:space:]]*"\*"'; then
      echo "[FAIL] $N — resource policy grants Principal \"*\""
    else
      echo "[!] $N — has a resource policy, review it: $POL"
    fi
  done
```

Any hit here is a different incident and is owned by
`../secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret/`.

#### Step 4 — Decide whether to rotate

If no retrieval succeeded, do not rotate. Rotation is disruptive, it consumes the `AWSPREVIOUS` slot
that a later incident may need, and the enumeration disclosed metadata rather than values. Rotate the
specific secrets Query 1 shows as successfully retrieved, and no others.

---

## 4. Eradication

### Remove Attacker Access

#### Scope `secretsmanager:ListSecrets` **and** `secretsmanager:DescribeSecret`

They are one capability. Granting `DescribeSecret` broadly while restricting `ListSecrets` leaves the
inventory readable one ARN at a time, and it is the grant most likely to survive a review because it
reads as harmless. Very few workloads need either: an application knows the ARN of the secret it
consumes and calls `GetSecretValue` directly.

#### Scope `GetSecretValue` by resource, not by service

```bash
ROLE="${1:?role name to scope}"
SECRET="${2:?secret name, e.g. prod/payments/db}"
REGION="${AWS_REGION:-us-east-1}"

# Secrets Manager appends a random six-character suffix to every secret ARN. An identity policy
# written against the bare name matches NOTHING and the grant fails silently, so the trailing `-*`
# is required rather than decorative. Confirm the real ARN before writing the policy:
aws secretsmanager describe-secret --secret-id "$SECRET" --region "$REGION" \
  --query 'ARN' --output text 2>/dev/null

ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
cat > /tmp/scoped-secret-read.json <<POLICY
{"Version":"2012-10-17","Statement":[{
  "Sid":"ReadOnlyTheSecretsThisWorkloadOwns",
  "Effect":"Allow",
  "Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],
  "Resource":["arn:aws:secretsmanager:${REGION}:${ACCT}:secret:${SECRET}-*"]}]}
POLICY

echo "[!] Review /tmp/scoped-secret-read.json, then attach it and REMOVE the broad grant that"
echo "    replaced it — adding a narrow policy beside a wildcard one changes nothing:"
echo "    aws iam put-role-policy --role-name $ROLE \\"
echo "      --policy-name ScopedSecretRead --policy-document file:///tmp/scoped-secret-read.json"
```

Note what this policy does **not** grant: `secretsmanager:ListSecrets`. An application knows the ARN
of the secret it consumes, so it never needs to enumerate.

#### Deny listing outside the operator path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenySecretsInventoryEnumeration",
  "Effect": "Deny",
  "Action": ["secretsmanager:ListSecrets"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourOperatorRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone. This one also breaks the Secrets Manager console for anybody outside the list, which is
usually the intent but should be a decision rather than a surprise. Note that it pushes an actor
toward `DescribeSecret`, which is why the correlation on that path exists. Test in a non-production
OU first.

#### Remove metadata from names, descriptions and tags

The inventory is reconnaissance because of what it says. `prod-stripe-live-key` tells an actor
everything before they read a byte. This is slow to fix and it is the only control that reduces the
value of a successful enumeration by either path.

---

## 5. Recovery

### Restore Clean State

#### Verify who can still enumerate

```bash
REGION="${AWS_REGION:-us-east-1}"
# POPULATE with the roles that are supposed to be able to enumerate.
EXPECTED="YourOperatorRole YourBreakGlassRole"

aws iam list-roles --query 'Roles[].RoleName' --output text 2>/dev/null | tr '\t' '\n' \
| while read -r R; do
    [ -z "$R" ] && continue
    ARN="$(aws iam get-role --role-name "$R" --query 'Role.Arn' --output text 2>/dev/null)"
    [ -z "$ARN" ] && { echo "[?] $R — could not read the role ARN; INCONCLUSIVE"; continue; }
    DEC="$(aws iam simulate-principal-policy --policy-source-arn "$ARN" \
            --action-names secretsmanager:ListSecrets --resource-arns '*' \
            --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null)"
    [ "$DEC" = "allowed" ] || continue
    MATCH=0
    for E in $EXPECTED; do [ "$R" = "$E" ] && MATCH=1; done
    [ "$MATCH" -eq 1 ] && echo "[OK] $R" || echo "[FAIL] $R can still list the inventory"
  done
```

#### Verify rotation is on where it matters

```bash
REGION="${AWS_REGION:-us-east-1}"

aws secretsmanager list-secrets --region "$REGION" --output json 2>/dev/null \
| jq -r '.SecretList[]
    | if .RotationEnabled then "[OK] \(.Name)"
      else "[FAIL] \(.Name) — rotation disabled; last rotated \(.LastRotatedDate // "never")" end'
```

A secret an actor enumerated and could not rotate away from is a secret that stays valuable. This is
the durable remediation for the metadata the enumeration disclosed, and it is owned operationally by
`../secretsmanager.persistence.rotation-disabled/`.

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"

# Exercise the DENIED-LISTING path, which the source building block cannot see. Run this as a
# principal WITHOUT secretsmanager:ListSecrets — an unprivileged test role, not your own session.
aws secretsmanager list-secrets --region "$REGION" >/dev/null 2>&1 \
  && echo "[!] the call SUCCEEDED — rerun as a principal without secretsmanager:ListSecrets" \
  || echo "[OK] denied — expect one alert with NO threshold, within 15 min"

echo "[!] Then exercise the DESCRIBE path against ten real secret names as a principal outside the"
echo "    consumer allowlist. If only the listing rule ever fires, an actor holding ARNs enumerates"
echo "    your inventory without tripping anything."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Did any `GetSecretValue` succeed? | The only question that changes the incident class, and it takes one query. |
| Was `ListSecrets` used at all, or only `DescribeSecret`? | The second path returns the same metadata and the source rules do not watch it. |
| How did the principal hold the enumeration permission? | Almost always through `secretsmanager:*` or a broad read-only policy nobody read closely. |
| What did the names and tags disclose? | The inventory is reconnaissance because of what it says, not because of what it returns. |
| Which enumerated secrets have rotation disabled? | Those are the ones whose current value stays valuable indefinitely. |
| Did the same session enumerate other services? | It changes the finding from a Secrets Manager incident to account mapping. |

### Recommended Guardrails

**Report a refused listing with no threshold.** There is no volume at which "asked for everything and
was told no" becomes more interesting.

**Cover `DescribeSecret` as an enumeration path.** Restricting `ListSecrets` alone moves the actor
onto a call most policies grant freely.

**Scope `GetSecretValue` by ARN, and remember the six-character suffix.** An ARN written without the
trailing `-*` matches nothing and the grant fails silently.

**Turn rotation on.** It is the only control that limits the value of a secret an actor has already
identified.

**Stop encoding the environment in secret names and tags.** It is slow, unglamorous, and it is what
makes a successful enumeration worth making.

### Technique Reference

**T1526 — Cloud Service Discovery.** Verified live at https://attack.mitre.org/techniques/T1526/ on
2026-08-31. Enumerating the resources a cloud service holds, before choosing a target, is what this
technique names.

**T1555.006 — Credentials from Password Stores: Cloud Secrets Management Stores.** Verified live
2026-08-31. It is the objective the enumeration serves and the technique the neighbouring retrieval
playbook carries.

`T1580 — Cloud Infrastructure Discovery` was considered and set aside: it is scoped to IaaS compute
and storage resources.

The source rules map `T1552 — Unsecured Credentials`. A credential store used as designed is not an
unsecured credential.

AWS references relied on throughout, all verified 2026-08-30:

- Secrets Manager CloudTrail logging — the statement that **all** API calls are recorded:
  https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html
- `ListSecrets` API reference — the response fields that make listing reconnaissance:
  https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html
- `DescribeSecret` API reference — the same metadata, one secret at a time:
  https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html

Service-wide verified behaviour shared by every `secretsmanager.*` playbook is in
`../_ground-truth/secretsmanager.md`.

### Residual Risk

**A principal with the ARNs does not need to enumerate at all.** An actor who already knows a
secret's name calls `GetSecretValue` directly and produces no enumeration signal. This playbook
covers the actor who has to look first.

**CloudTrail does not record what the enumeration returned.** The inventory the actor saw is
reconstructed from your side and may differ from theirs if permissions changed in between.

**`simulate-principal-policy` does not evaluate secret resource policies for cross-account
principals.** The "what could they have read" list in Step 2 is a floor, not a ceiling.

**Denying `ListSecrets` pushes the actor onto `DescribeSecret`.** The guardrail and the blind spot are
the same control, which is why the `DescribeSecret` correlation ships alongside it rather than after
an incident.
