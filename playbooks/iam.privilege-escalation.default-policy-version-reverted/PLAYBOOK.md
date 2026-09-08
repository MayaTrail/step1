# IR Playbook: IAM Managed Policy Default Version Changed — escalation via `SetDefaultPolicyVersion`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Privilege escalation — the operative version of a managed policy is changed, re-permissioning every user, group and role it is attached to, without any policy text being written |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High for a single activation; critical when a version is authored and activated as two steps, or when the activated version grants `Action: "*"`. The source rule rates it P2 with no MITRE mapping. |
| MITRE Tactics | Persistence; Privilege Escalation |
| MITRE Techniques | T1098.003 |
| Services in Scope | IAM, CloudTrail, AWS Organizations |

**What the technique does:** the actor points a managed policy at a different version.
`SetDefaultPolicyVersion` takes `PolicyArn` and `VersionId` — **and nothing else**. There is no
policy document on the request, because the permissive text already exists: a managed policy holds
up to five versions, so up to four non-operative ones linger at any time, and an over-broad draft
that was tightened months ago is still there waiting.

AWS: *"This operation affects all users, groups, and roles that the policy is attached to."* One
call, every attached principal, no policy edit.

**Why the usual reflexes miss it.** The first is to inspect `policyDocument` — the two sibling rules
in the same source pack both do, and neither can see this technique because the field does not exist
on this call. The second is to watch `SetDefaultPolicyVersion` alone: `CreatePolicyVersion` with
`SetAsDefault: true` reaches the same end state in one call and emits no `SetDefaultPolicyVersion`
event at all. The third is to rate the event without establishing blast radius, which is not in it —
the same call is a non-issue on a policy attached to nothing and an account-wide escalation on one
attached to a hundred roles. The fourth is to expect a change review to have caught it: nothing was
written, so there is no diff.

**Detection thesis:** cover both call names, rate on the direction of the version change, and
resolve blast radius with `ListEntitiesForPolicy` before rating anything.

**Adjacent playbooks.** Writing a permissive version is
`../iam.privilege-escalation.policy-version-overly-permissive/`. Attaching an existing policy to a
principal is `../iam.privilege-escalation.admin-policy-attached/`. Inline policies are
`../iam.privilege-escalation.inline-policy-grant/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

**A multi-Region CloudTrail with `IncludeGlobalServiceEvents`.** IAM is a global service: its events
are recorded in `us-east-1` and CloudTrail delivers global service events *only* to single-Region
trails there. A single-Region trail anywhere else receives **no IAM events at all**, so every rule in
this playbook is silently inert. This is the prerequisite that most often turns out to be missing.

A recorded baseline of which version each customer-managed policy is expected to run, and which
policies are attached to privileged principals. The event does not carry blast radius, so the
inventory is what turns an alert into a rating.

AWS Config with `iam-policy-no-statements-with-admin-access`, which records policy *state* over time
and will show a version change that CloudTrail alone describes only as an ARN and a version number.

**Alerting (must be pre-configured)**

- **`CreatePolicyVersion` with `setAsDefault: true` whose document contains `Action: "*"` → P0**
- **`CreatePolicyVersion` left dormant, then `SetDefaultPolicyVersion` by the same principal within 1h → P0**
- **`SetDefaultPolicyVersion` moving to a lower version number than the previous default → P0**

**Response Tooling**

An IAM principal that can call `iam set-default-policy-version`, `get-policy-version`,
`list-policy-versions` and `list-entities-for-policy` outside the change pipeline.

`tools/decode_policy_documents.py`, because `GetPolicyVersion` returns a percent-encoded document
while the CloudTrail request parameters are raw JSON — decoding the wrong one corrupts it
(authoring rule A4).

**Known IOC Baselines**

The roles that own IAM policy lifecycle, populating `known_provisioners`. Every infrastructure apply
that updates a managed policy calls `CreatePolicyVersion` with `setAsDefault: true`, so without this
list the second rule fires on every deployment.

The set of policies attached to break-glass or administrative principals. A version change on one of
those is a different incident from a version change on an application policy.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `CreatePolicyVersion` with `setAsDefault: true` whose document grants `Action: "*"` | CloudTrail | T1098.003 |
| P0 | `CreatePolicyVersion` left dormant, then `SetDefaultPolicyVersion` by the same principal within 1h | Correlation rule | T1098.003 |
| P0 | `SetDefaultPolicyVersion` moving the default to a **lower** version number — a revert to text no review saw | CloudTrail + `ListPolicyVersions` | T1098.003 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `SetDefaultPolicyVersion` by a principal not on the recorded provisioner list | CloudTrail | T1098.003 |
| P2 | `CreatePolicyVersion` with `setAsDefault: true` by a principal not on the recorded provisioner list | CloudTrail | T1098.003 |
| P2 | `DeletePolicyVersion` immediately before a `CreatePolicyVersion` on the same policy — the five-version limit being cleared, which also destroys the deleted version's content | CloudTrail | T1098.003 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Watches `SetDefaultPolicyVersion` only | `CreatePolicyVersion` with `SetAsDefault: true` reaches the same end state in one call and emits no `SetDefaultPolicyVersion` event. The most direct form of the technique is invisible | A second rule on the create-and-activate form, which is also the only shape where the granted permissions are readable from the event |
| No blast-radius resolution | AWS: *"This operation affects all users, groups, and roles that the policy is attached to"* — and names none of them. The same event is a non-issue or an account-wide escalation depending on attachments | `ListEntitiesForPolicy` in §2 Query 2, run before the finding is rated, per AWS's own guidance in the same paragraph |
| No direction check | The event carries `versionId`, and a move to a **lower** number is a revert to text that was previously replaced — no author, no diff, no review. A forward move is usually a deployment | Version numbers compared against `ListPolicyVersions`; the backwards move is rated above the forward one |
| No pairing of create with activate | Splitting the two calls separates a reviewable create from an unreviewed activation. Each half alone reads as ordinary | A `temporal_ordered` correlation over 1h, grouped by principal |
| No principal filter | Every infrastructure apply that updates a managed policy is `CreatePolicyVersion` with `setAsDefault: true` | `known_provisioners` on both alerting rules, shipped with placeholders that must be populated |
| Rated P2, MITRE: none | An operation that re-permissions every attached principal, rated below the pack's own bucket-policy rules | High for a single activation, critical for the pair; `T1098.003` |

**Recommended detection — both call names, and the split that separates author from activate.**

```yaml
# IAM managed policy default version changed (T1098.003)
#
# THIS CALL GRANTS PERMISSIONS AND CARRIES NONE. SetDefaultPolicyVersion takes PolicyArn and
# VersionId, and nothing else — there is no policyDocument on the request. Every "overly permissive
# policy" rule in the same source pack inspects policyDocument, so all of them are structurally
# blind to this technique. The permissive text was authored earlier, possibly legitimately, and
# activating it writes nothing.
#
# THE SOURCE RULE WATCHES ONE OF THE TWO CALLS THAT DO THIS. `CreatePolicyVersion` with
# `SetAsDefault: true` makes the new version operative in a SINGLE call — AWS: "When this parameter
# is true, the new policy version becomes the operative version" — and emits no
# SetDefaultPolicyVersion event at all. A rule scoped to SetDefaultPolicyVersion misses the more
# direct form entirely. Both are covered below.
#
# AND ITS BLAST RADIUS IS UNBOUNDED AND UNKNOWABLE FROM THE EVENT. AWS: "This operation affects all
# users, groups, and roles that the policy is attached to." One call re-permissions every attached
# principal. The event names none of them; ListEntitiesForPolicy is AWS's own documented way to find
# out, and §2 of ../PLAYBOOK.md runs it.
#
# WHY OLD VERSIONS ARE THE INTERESTING ONES. A managed policy holds up to five versions, so up to
# four non-operative ones linger at any time. An over-broad draft that was tightened months ago is
# still there, and one call makes it live again — with no policy edit for a change-review process to
# catch. VersionId matches v[1-9][0-9]*, so a LOWER number than the current default is a revert
# backwards, which is the direction worth rating higher.
title: IAM managed policy default version changed
id: 3fa71c08-6b25-4e19-9d4a-08c3e7b512df
name: iam_default_policy_version_changed
status: experimental
description: >-
  SetDefaultPolicyVersion succeeded. The operative version of a managed policy changed, which
  re-permissions every user, group and role the policy is attached to at once. The event carries no
  policy document, so what was granted is not knowable without GetPolicyVersion, and the affected
  principals are not knowable without ListEntitiesForPolicy.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_SetDefaultPolicyVersion.html
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
  - https://attack.mitre.org/techniques/T1098/003/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'SetDefaultPolicyVersion'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own IAM policy lifecycle.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A rollback of a policy change that broke something, which legitimately reverts to an earlier
    version. It should correlate with an incident or a deployment, and it is indistinguishable from
    the attack without that context — which is why the response starts by reading the version rather
    than by judging the caller.
level: high
---
title: IAM managed policy version created and activated in one call
id: 8c2d40b7-91ae-4f63-b508-27d1a6ef9430
name: iam_policy_version_created_as_default
status: experimental
description: >-
  CreatePolicyVersion succeeded with setAsDefault true. This is the same escalation as
  SetDefaultPolicyVersion and it produces no SetDefaultPolicyVersion event, so a rule watching that
  name alone never sees it. Unlike the revert case the document IS on this request, which makes it
  the one shape here where the granted permissions can be read directly from the event.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
  - https://attack.mitre.org/techniques/T1098/003/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  # Three keys ANDed, and they do co-occur on a single event: a CreatePolicyVersion record carries
  # eventSource, eventName and the submitted setAsDefault flag together.
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreatePolicyVersion'
    requestParameters.setAsDefault: true
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    An infrastructure apply that updates a managed policy, which is exactly this call. Allowlisting
    the provisioning role is mandatory rather than optional here; without it this rule fires on
    every policy deployment.
level: high
---
title: IAM policy version authored and then activated by the same principal
id: b6019f5c-4d38-42a7-8e10-c39d75a4b28e
status: experimental
description: >-
  A principal created a new managed policy version and then made it the default in a separate call.
  Splitting the two steps is what an actor does when the create is expected to be reviewed and the
  activation is not — the version sits dormant and harmless until the second call, at which point it
  applies to every attached principal. The pair is the finding; each half alone has an ordinary
  reading.
references:
  - https://attack.mitre.org/techniques/T1098/003/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.003
correlation:
  type: temporal_ordered
  rules:
    - iam_policy_version_created
    - iam_default_policy_version_changed
  group-by:
    - userIdentity.arn
  timespan: 1h
falsepositives:
  - >-
    A deployment that creates a version and promotes it as two steps. Allowlist the pipeline role on
    the base rules rather than shortening the timespan — a patient actor is exactly who a short
    timespan lets through.
level: critical
---
title: IAM managed policy version created
id: 5e83b21d-7c04-4906-a2f5-1db608e73c4a
name: iam_policy_version_created
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful
  CreatePolicyVersion, including one left dormant. AWS caps a managed policy at five versions, so
  routine policy maintenance produces these continuously.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
tags:
  - attack.persistence
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreatePolicyVersion'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: for the `SetDefaultPolicyVersion` form it cannot say what was
granted, because the request carries no document. That is resolved by `GetPolicyVersion` in §2 Query
2, not by any rule.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> IAM is a **global service**: run these in `us-east-1`, where its events are recorded.

Run Query 1 first; it produces the policy ARN and version that Query 2 resolves.

#### Query 1 — Reconstruct: which call, which version, and in which direction

```bash
REGION="us-east-1"   # IAM events are global-service events, recorded here
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in SetDefaultPolicyVersion CreatePolicyVersion DeletePolicyVersion; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # setAsDefault true on a create is the SAME escalation as SetDefaultPolicyVersion, in one
      # call and under a different event name. Absent means the version is dormant and grants
      # nothing until a later activation.
      | (if .eventName == "CreatePolicyVersion" and ($r.setAsDefault == true) then "CREATE+ACTIVATE"
         elif .eventName == "CreatePolicyVersion" then "create (dormant)"
         elif .eventName == "SetDefaultPolicyVersion" then "ACTIVATE"
         else "delete-version" end) as $kind
      # The document exists on create and NOT on activate — that asymmetry is the technique.
      | (if ($r.policyDocument // "") == "" then "no-document" else "document-present" end) as $doc
      | "\(.eventTime)  \($kind)  \(.userIdentity.arn)  \($doc)  " +
        "policy=\($r.policyArn // "-")  version=\($r.versionId // "-")  ip=\(.sourceIPAddress)"'
done | sort
```

Read the `version=` column as a sequence per policy. A move to a **lower** number is a revert to
text that was previously replaced — nothing was authored, so no diff exists and no review saw it.
A `create (dormant)` followed later by an `ACTIVATE` on the same policy is the two-step form.

#### Query 2 — Resolve what was granted, and to whom

```bash
POLICY_ARN="${1:?policy ARN from Query 1 required}"
VERSION="${2:?version id from Query 1 required}"

echo "=== Who this affects — AWS's own answer to blast radius ==="
aws iam list-entities-for-policy --policy-arn "$POLICY_ARN" --output json 2>/dev/null \
| jq -r '"  roles:  \([.PolicyRoles[].RoleName]  | join(", ") // "none")",
         "  users:  \([.PolicyUsers[].UserName]  | join(", ") // "none")",
         "  groups: \([.PolicyGroups[].GroupName] | join(", ") // "none")"'

echo
echo "=== Every version, and which is operative now ==="
aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
  --query 'Versions[].[VersionId,IsDefaultVersion,CreateDate]' --output text 2>/dev/null | sort

echo
echo "=== What the activated version actually grants ==="
# GetPolicyVersion RETURNS a percent-encoded document — unlike requestParameters, which are raw.
# Decode conditionally: only input that actually begins '%'. See authoring rule A4.
aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$VERSION" \
  --query 'PolicyVersion.Document' --output text 2>/dev/null \
| python3 -c '
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
if raw.startswith("%"):
    raw = urllib.parse.unquote(raw)
doc = json.loads(raw)
stmts = doc.get("Statement", [])
if isinstance(stmts, dict):
    stmts = [stmts]
for s in stmts:
    act = s.get("Action"); res = s.get("Resource")
    act = act if isinstance(act, list) else [act]
    res = res if isinstance(res, list) else [res]
    # Action "*" is administrative. Resource "*" is NOT — many legitimate actions accept no other
    # value. Rating them alike is the largest false-positive source in the source pack.
    flag = "[!] ADMIN" if (s.get("Effect") == "Allow" and "*" in act) else "[ ]"
    print("%s %s  Action=%s  Resource=%s" % (flag, s.get("Effect"), act[:4], res[:2]))
'
```

The three blocks answer three different questions and the order matters: how many principals this
touched, whether the version moved backwards, and only then what it grants. Rating the event before
running the first block is the most common way this gets mis-triaged in both directions.

#### Query 3 — Sweep: which policies are not running their newest version

```bash
aws iam list-policies --scope Local --query 'Policies[].[Arn,DefaultVersionId]' \
  --output text 2>/dev/null | while IFS=$'\t' read -r ARN DEFV; do
    [ -z "$ARN" ] && continue
    NEWEST="$(aws iam list-policy-versions --policy-arn "$ARN" \
               --query 'Versions[].VersionId' --output text 2>/dev/null \
             | tr '\t' '\n' | sed 's/^v//' | sort -n | tail -1)"
    CUR="${DEFV#v}"
    if [ -n "$NEWEST" ] && [ "$CUR" -lt "$NEWEST" ] 2>/dev/null; then
      echo "[!] $ARN — operative v$CUR but v$NEWEST exists (running an older version)"
    else
      echo "[OK] $ARN — operative $DEFV"
    fi
  done
```

An `[!]` row is not automatically an incident: reverting after a bad deployment is legitimate and
leaves exactly this state. It is the population worth reviewing, and on most accounts it is short
enough to review by hand — which is the point, because there is no other way to find a revert that
happened before logging was in place.

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"
REGION="us-east-1"
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

Look for `ListPolicyVersions` and `GetPolicyVersion` **before** the activation. Finding a dormant
permissive version requires reading them, and that reconnaissance is the earliest signal available.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Revert the default version first — it is one call and it removes the granted permissions from every
attached principal at once, which is faster than touching the principals individually.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 shows the policy
is attached to an administrative or break-glass role, treat the escalation as account-wide: the
activated version applies to that role's sessions immediately, and existing sessions carry the new
permissions without re-authenticating.

#### Step 1 — Revert to the correct version

```bash
POLICY_ARN="${1:?policy ARN required}"
GOOD_VERSION="${2:?the version that SHOULD be operative}"

# Confirm the target is what you think before switching to it. The safe version is not always the
# highest number — if the escalation used CreatePolicyVersion, the newest version IS the bad one.
aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$GOOD_VERSION" \
  --query 'PolicyVersion.Document' --output text 2>/dev/null \
| python3 -c '
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
if raw.startswith("%"): raw = urllib.parse.unquote(raw)
doc = json.loads(raw); stmts = doc.get("Statement", [])
if isinstance(stmts, dict): stmts = [stmts]
admin = [s for s in stmts if s.get("Effect") == "Allow"
         and "*" in (s.get("Action") if isinstance(s.get("Action"), list) else [s.get("Action")])]
print("[FAIL] target version ALSO grants Action:* — pick a different one" if admin
      else "[OK] target version has no Allow on Action:*")
'

read -r -p "Proceed to make $GOOD_VERSION operative on $POLICY_ARN? [y/N] " ANS
[ "$ANS" = "y" ] && aws iam set-default-policy-version \
  --policy-arn "$POLICY_ARN" --version-id "$GOOD_VERSION" \
  && echo "[OK] $POLICY_ARN reverted to $GOOD_VERSION"
```

The confirmation prompt is deliberate. This call re-permissions every attached principal, so an
error here has the same blast radius as the incident — including the possibility of breaking a
production workload that legitimately needed the newer version.

#### Step 2 — Preserve the offending version before it can be deleted

```bash
POLICY_ARN="${1:?policy ARN required}"
BAD_VERSION="${2:?the version that was activated}"
OUT="./evidence-$(basename "$POLICY_ARN")-${BAD_VERSION}.json"

# A managed policy holds at most five versions, so an actor who wants to author another must delete
# one first — and a deleted version's content is unrecoverable. Capture it now.
aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$BAD_VERSION" \
  --output json > "$OUT" 2>/dev/null \
  && echo "[OK] version preserved at $OUT" \
  || echo "[FAIL] could not read $BAD_VERSION — it may already have been deleted"

aws iam list-policy-versions --policy-arn "$POLICY_ARN" --output json 2>/dev/null \
  > "./evidence-$(basename "$POLICY_ARN")-versions.json" \
  && echo "[OK] version list preserved"
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

#### Step 4 — Establish what the escalated principals did with the permissions

Every principal Query 2 listed held the elevated permissions for the whole window between activation
and Step 1. Work each one's session history over that interval, not just the principal that made the
change — the actor who activates a policy version and the principal that benefits from it are
frequently not the same, and the beneficiary is the one that matters.

```bash
START="${1:?activation timestamp from Query 1}"
END="${2:?revert timestamp from Step 1}"
REGION="us-east-1"

# Feed each name from Query 2's list-entities-for-policy output.
for NAME in "${@:3}"; do
  echo "=== $NAME ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue="$NAME" \
    --start-time "$START" --end-time "$END" --region "$REGION" \
    --query 'Events[].[EventTime,EventName,EventSource]' --output text 2>/dev/null | sort
done
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete the permissive version, deliberately

Reverting the default leaves the escalated version in place, one call away from being operative
again — and that call is the technique. Once Step 2 has preserved its content, delete it:

```bash
aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$BAD_VERSION"
```

Do this only after the evidence capture, because deletion is irreversible and no AWS API returns a
deleted version's document.

#### Audit every other version of every policy the principal could reach

The technique needs a permissive version to exist. Query 3's sweep finds policies not running their
newest version; the complementary check is policies whose **non-default** versions grant
`Action: "*"`. Those are pre-loaded escalations waiting for one call, and they are invisible to
every rule that inspects policies at write time.

#### Separate authoring from activation

`iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` are distinct actions and can be granted
to distinct principals. A pipeline that authors versions and a change-approval path that activates
them removes the single-actor form of this technique entirely — and makes the correlation in §2 the
only remaining shape, which is exactly what it is designed to catch.

#### Deny the operation outside a break-glass path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyPolicyVersionActivation",
  "Effect": "Deny",
  "Action": ["iam:SetDefaultPolicyVersion", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline that legitimately needs it. Test in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify the operative version and its contents

```bash
POLICY_ARN="${1:?policy ARN required}"
EXPECT="${2:?the version that should be operative}"

CUR="$(aws iam get-policy --policy-arn "$POLICY_ARN" \
        --query 'Policy.DefaultVersionId' --output text 2>/dev/null)"
if [ "$CUR" = "$EXPECT" ]; then
  echo "[OK] operative version is $CUR"
else
  echo "[FAIL] operative version is $CUR, expected $EXPECT"
fi

aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$CUR" \
  --query 'PolicyVersion.Document' --output text 2>/dev/null \
| python3 -c '
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
if raw.startswith("%"): raw = urllib.parse.unquote(raw)
stmts = json.loads(raw).get("Statement", [])
if isinstance(stmts, dict): stmts = [stmts]
bad = [s for s in stmts if s.get("Effect") == "Allow"
       and "*" in (s.get("Action") if isinstance(s.get("Action"), list) else [s.get("Action")])]
print("[FAIL] operative version still grants Allow on Action:*" if bad
      else "[OK] operative version has no Allow on Action:*")
'
```

#### Verify the permissive version is gone, not merely inactive

```bash
POLICY_ARN="${1:?policy ARN required}"
BAD_VERSION="${2:?the version that was activated}"

if aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$BAD_VERSION" \
     >/dev/null 2>&1; then
  echo "[FAIL] $BAD_VERSION still exists — one set-default-policy-version call re-enables it"
else
  echo "[OK] $BAD_VERSION deleted"
fi
```

This is the check that distinguishes recovered from suppressed. A reverted default with the
permissive version still present is the same situation as before the incident, minus the actor's
first call.

#### Confirm the corrected detection fires

```bash
POLICY_ARN="${1:?a NON-PRODUCTION policy ARN attached to nothing}"

# Exercise the CREATE+ACTIVATE form — the one the source rule cannot see — with a harmless
# document. The policy is attached to nothing, so activating it grants nobody anything.
aws iam create-policy-version --policy-arn "$POLICY_ARN" --set-as-default \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}' \
  && echo "[OK] created and activated — expect the create-and-activate rule within 15 min"

echo "[!] A Deny-only document is used deliberately: it exercises the event shape without granting"
echo "    anything, and it also tests that the rule does not treat Deny as an escalation."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Which call was used — activate, or create-and-activate? | The second emits no `SetDefaultPolicyVersion` event. If it was used and nothing fired, the coverage gap is the finding. |
| Did the version number move backwards? | A revert means the permissive text already existed and no review ever saw it — which changes who is accountable. |
| How many principals did `ListEntitiesForPolicy` return? | This is the blast radius, and it is not in the event. A rating made without it is a guess. |
| Was the permissive version authored by the same principal? | Author and activator being different is the two-step form; being the same makes the create the earlier signal. |
| Does a multi-Region trail with global service events exist? | If not, none of this was ever being logged, and the incident was found some other way. |
| Was the permissive version deleted after reverting? | If not, the account is one call from the same state. |

### Recommended Guardrails

**Split `CreatePolicyVersion` from `SetDefaultPolicyVersion`.** They are distinct IAM actions.
Granting them to different principals removes the single-actor form of this technique and leaves only
the correlated one, which is detectable.

**Audit non-default versions, not just operative ones.** A dormant `Action: "*"` version is a
pre-loaded escalation that every write-time policy check misses, because nothing is being written.

**Confirm a multi-Region trail with `IncludeGlobalServiceEvents` exists.** IAM events reach only
`us-east-1` trails. This is the prerequisite most likely to be quietly absent, and its absence makes
every IAM detection in the estate inert while the coverage dashboard stays green.

**Alert on the direction, not just the event.** A forward version move is a deployment; a backward
one is a revert to text nobody reviewed. The event carries the version number, so the distinction
is free.

**Delete versions you have deprecated.** The five-version limit means old text lingers by default.
Deleting a superseded permissive version is a one-line hygiene task that removes the material this
technique depends on.

### Technique Reference

**T1098.003 — Account Manipulation: Additional Cloud Roles.** Verified live at
https://attack.mitre.org/techniques/T1098/003/ on 2026-08-30. The operation adds permissions to
existing principals, which is what this sub-technique names.

**T1484 — Domain or Tenant Policy Modification** was considered and set aside. It is written for
directory and tenant-level policy rather than an identity policy attached to principals; an AWS SCP
would fit it better than a managed policy does. Verified live 2026-08-30.

The source rule carried **no** MITRE mapping.

AWS references relied on throughout, all verified 2026-08-30:

- `SetDefaultPolicyVersion` — the parameter list with no policy document, the statement that it
  affects every attached principal, and the `ListEntitiesForPolicy` guidance:
  https://docs.aws.amazon.com/IAM/latest/APIReference/API_SetDefaultPolicyVersion.html
- `CreatePolicyVersion` — the five-version limit and the `SetAsDefault` semantics:
  https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html

Service-wide verified behaviour shared by every `iam.*` playbook is in `../_ground-truth/iam.md`.

### Residual Risk

**The activation event will never carry what was granted.** No configuration changes this — the
request genuinely has no document field. Every response here depends on `GetPolicyVersion` being
reachable, and on the version still existing when it is called.

**A deleted version's content is unrecoverable.** If the actor deletes the permissive version after
reverting, or to make room under the five-version cap, no AWS API returns it. The CloudTrail
`CreatePolicyVersion` event that authored it is the only remaining copy, and only if it happened
inside the retention window.

**A legitimate rollback is indistinguishable at the event level.** Reverting after a bad deployment
produces exactly this signal, including the backwards version move. The §1 baseline of expected
versions is the only thing that separates them, and where it does not exist this alert will be
closed as a rollback every time — including when it is not one.

**AWS-managed policies are out of scope.** Their versions are controlled by AWS and cannot be
activated by a customer principal, so the sweep in Query 3 deliberately uses `--scope Local`. A
principal attaching an AWS-managed administrative policy is a different technique, covered in
`../iam.privilege-escalation.admin-policy-attached/`.
