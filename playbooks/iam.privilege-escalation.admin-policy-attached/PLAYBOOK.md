# IR Playbook: Administrative Policy Attached to a Principal — `AttachRolePolicy` and its siblings

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Privilege escalation — an administrative managed policy is attached to a user, role or group, granting its permissions immediately |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical for an administrative policy or a fan-out across principals; high for any group attachment, whose blast radius is unbounded and not in the event. The source pack rates the flow P3 and its components as building blocks. |
| MITRE Tactics | Persistence; Privilege Escalation |
| MITRE Techniques | T1098.003 |
| Services in Scope | IAM, CloudTrail, IAM Identity Center, AWS Organizations |

**What the technique does:** the actor attaches an existing managed policy to a principal. There are
three event names — `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy` — for the three
principal types IAM has, and they are one operation with one response. The permissions apply
immediately, including to sessions already in flight for a role.

**Why the usual reflexes miss it.** The first is to define "administrative" as a policy name:
`AdministratorAccess` as a substring misses `PowerUserAccess`, `IAMFullAccess` and every home-grown
policy granting `Action: "*"`, while matching anything merely named after it. The second is to
filter the three event names differently — the source pack excludes CloudFormation and SSO on roles
and nothing on users, which makes an SSO-driven escalation invisible on one path and visible on
another for no stated reason. The third is to rate a group attachment like a user attachment: a
group grant reaches every current **and future** member, and future members produce no event at all.
The fourth is to detach and consider it closed, when existing role sessions keep the permissions
until they expire.

**Detection thesis:** define administrative from the account's policy documents rather than from
names, filter the three paths identically, and rate group attachments above individual ones.

**Adjacent playbooks.** Authoring the permissive policy in the first place is
`../iam.privilege-escalation.policy-version-overly-permissive/`; activating an existing permissive
version is `../iam.privilege-escalation.default-policy-version-reverted/`; embedding permissions
directly on a principal is `../iam.privilege-escalation.inline-policy-grant/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

**A multi-Region CloudTrail with `IncludeGlobalServiceEvents`.** IAM is a global service: its events
are recorded in `us-east-1` and are delivered only to trails that include global service events.
Without one, every rule here is silently inert.

**The account's real administrative-policy list**, derived by reading policy documents rather than
by matching names. This is the single prerequisite that determines whether the critical rule works:
shipped with only the AWS-managed entries, it under-reports by exactly the number of home-grown
administrative policies in the account, and that number is rarely zero. §4 derives it.

Group membership exported on a schedule. A group attachment's blast radius is its members, and
`GetGroup` gives you today's — the ones added tomorrow inherit the grant silently.

**Alerting (must be pre-configured)**

- **An administrative policy attached to any principal → P0**
- **A principal attaching an administrative policy to itself → P0**
- **Policies attached to three or more distinct principals by one identity within an hour → P0**

**Response Tooling**

An IAM principal that can call `iam detach-role-policy`, `detach-user-policy`,
`detach-group-policy`, `get-group`, `list-attached-role-policies` and `put-role-policy` outside the
change pipeline.

**Known IOC Baselines**

The roles that own IAM lifecycle, populating `known_provisioners`. Group-based permission management
is a recommended practice and produces `AttachGroupPolicy` routinely, so without this list the group
rule is unusable.

The list of principals that are administrative **by design** — break-glass roles, the provisioning
role itself. An administrative policy attached to one of those is expected; to anything else it is
the incident.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | A policy on the account's administrative list attached to any principal | CloudTrail | T1098.003 |
| P0 | A principal attaching an administrative policy to **itself** — caller ARN and grantee are the same identity | CloudTrail (field comparison) | T1098.003 |
| P0 | Policies attached to three or more distinct principals by one identity within an hour | Correlation rule | T1098.003 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | Any policy attached to a group by a principal not on the provisioner list — every current and future member inherits it | CloudTrail + `GetGroup` | T1098.003 |
| P2 | A policy authored and then attached by the same principal within the hour | CloudTrail | T1098.003 |
| P2 | A customer-managed policy attached that is not on the administrative list — which does not mean it is not administrative | CloudTrail | T1098.003 |

### Detection Rule Quality Notes

The five source rules are threshold queries and a flow, all fully readable, so every row below is
auditable against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `policyArn:AdministratorAccess` as a substring | Misses `PowerUserAccess`, `IAMFullAccess` and every customer-managed policy granting `Action: "*"`; matches anything merely named after it. The definition of administrative is a hardcoded string | An explicit list, with §4 deriving the account's real one by reading policy documents |
| Three event names, three different service-principal filters | `AttachRolePolicy` excludes CloudFormation and SSO; the other two exclude nothing. An SSO-driven escalation is invisible on roles and visible on users, for no stated reason | One consistent `invokedBy` exclusion across all three, stated in the rule so it can be argued with |
| Group attachment rated like a user attachment | `AttachGroupPolicy` grants to every current **and future** member. Current members need `GetGroup`; future members produce no event at all | Its own rule one level higher, and a playbook step that removes rather than monitors |
| The flow references components by opaque numeric ID | `(49 AND 33) OR (49 AND 27)` cannot be audited against anything, and is rated P3 — below the P2 its siblings carry | A named `value_count` correlation on fan-out across distinct principals, which is the volume dimension the pack has nowhere |
| No success filter on any of the five | A denied attach is a different finding from a successful one, and the rules cannot tell them apart | `errorCode: null` on every alerting rule |
| MITRE: none on all five | | `T1098.003` |

**Recommended detection — the three paths as one use case, rated by blast radius.**

```yaml
# Administrative managed policy attached to a principal (T1098.003)
#
# MERGE TEST — WHY FIVE SOURCE RULES BECOME ONE USE CASE. AttachUserPolicy, AttachRolePolicy and
# AttachGroupPolicy are the same operation against the three principal types IAM has. The pack ships
# them as three building blocks plus an "Admin Policy Attached" block plus a flow that combines them
# by opaque numeric ID. Splitting them further would produce three playbooks with one identical
# response; the blast-radius difference between them is a severity dimension, not a use case.
#
# "ADMINISTRATIVE" IS NOT ONE POLICY NAME, AND THE SOURCE RULE TREATS IT AS ONE.
# It matches `requestParameters.policyArn:AdministratorAccess` — a SUBSTRING on the ARN. That fails
# in both directions:
#   * It MISSES PowerUserAccess, IAMFullAccess, and every customer-managed policy granting
#     Action:"*" under a name like `AppRuntimePolicy`. Attaching any of those is the same escalation.
#   * It MATCHES a customer-managed policy merely NAMED something containing AdministratorAccess.
# The list below must be populated from the account, not assumed — §4 of ../PLAYBOOK.md derives it.
#
# THE THREE RULES FILTER SERVICE PRINCIPALS THREE DIFFERENT WAYS, FOR NO STATED REASON.
# AttachRolePolicy excludes userIdentity.invokedBy cloudformation.amazonaws.com and
# sso.amazonaws.com. AttachUserPolicy and AttachGroupPolicy exclude nothing. Same operation, three
# filters. The SSO exclusion matters most: an escalation performed through SSO's role provisioning
# is invisible on roles and visible on users, which is an arbitrary blind spot rather than a
# decision. One consistent exclusion is applied below, and it is stated.
#
# ATTACHING TO A GROUP ESCALATES EVERY MEMBER, AND THE EVENT NAMES NONE OF THEM.
# AttachGroupPolicy has the largest blast radius of the three and the pack rates it identically to
# the other two. Like SetDefaultPolicyVersion, the affected principals require a second API call —
# GetGroup — to enumerate. It ships one level higher here for that reason alone.
title: Administrative managed policy attached to a principal
id: 4e7c1a95-0d38-4b62-97fa-c1e5806b23df
name: iam_admin_policy_attached
status: experimental
description: >-
  A successful AttachUserPolicy, AttachRolePolicy or AttachGroupPolicy of a policy on the recorded
  administrative list. This is a direct grant of administrative permissions to a principal. The
  policy list is deliberately explicit rather than a substring on "AdministratorAccess", because
  that name is neither necessary nor sufficient — PowerUserAccess and IAMFullAccess do not contain
  it, and a customer-managed policy can contain it without being administrative.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html
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
    eventName:
      - 'AttachUserPolicy'
      - 'AttachRolePolicy'
      - 'AttachGroupPolicy'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING. The AWS-managed entries below are a starting point, not the list —
  # §4 of ../PLAYBOOK.md derives the customer-managed policies that also grant Action:"*", and those
  # are usually the ones that matter in a mature account.
  administrative_policies:
    requestParameters.policyArn:
      - 'arn:aws:iam::aws:policy/AdministratorAccess'
      - 'arn:aws:iam::aws:policy/PowerUserAccess'
      - 'arn:aws:iam::aws:policy/IAMFullAccess'
  # One consistent service-principal exclusion across all three event names, rather than the
  # source pack's three different ones. Stated so it can be argued with.
  service_invoked:
    userIdentity.invokedBy|exists: true
  condition: selection and success and administrative_policies and not service_invoked
falsepositives:
  - >-
    A break-glass role being provisioned, or an administrator onboarding. Both should be rare and
    both should leave a change record; if neither is true, the account's administrative grants are
    not being controlled and that is the finding rather than the event.
level: critical
---
title: Managed policy attached to an IAM group
id: 2a90f5e7-63b4-41cd-8e02-7db419fa5c86
name: iam_policy_attached_to_group
status: experimental
description: >-
  A successful AttachGroupPolicy of any policy. This has the largest blast radius of the three
  attach operations — every current and future member of the group receives the permissions — and
  the event names no members at all, so resolving it requires GetGroup. The source pack rates it
  identically to attaching to a single user. Shipped above the informational base rule and below
  the administrative-policy rule, which supersedes it when both match.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachGroupPolicy.html
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
    eventName: 'AttachGroupPolicy'
  success:
    errorCode: null
  service_invoked:
    userIdentity.invokedBy|exists: true
  # POPULATE BEFORE DEPLOYING with the roles that own IAM lifecycle.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not service_invoked and not known_provisioners
falsepositives:
  - >-
    Group-based permission management, which is a recommended practice and produces this event
    routinely. The provisioner allowlist is what makes this rule usable; without it, an estate that
    manages permissions by group will see it constantly.
level: high
---
title: Policies attached to many principals by one identity
id: 8f21d604-b97e-4a53-b0c6-3e58472ad91b
status: experimental
description: >-
  One principal attached policies to three or more distinct principals within an hour. Any single
  attachment has an ordinary reading; a fan-out does not, and it is the shape that matters when an
  actor is establishing access across several identities rather than escalating one. The source
  pack has no volume dimension at all.
references:
  - https://attack.mitre.org/techniques/T1098/003/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.003
correlation:
  type: value_count
  rules:
    - iam_policy_attached
  group-by:
    - userIdentity.arn
  timespan: 1h
  condition:
    gte: 3
    field: requestParameters.policyArn
falsepositives:
  - >-
    An environment build that attaches policies across many roles in one run. Allowlist the pipeline
    role on the base rule rather than raising the threshold — three is already permissive for a
    human operator.
level: critical
---
title: IAM managed policy attached to a principal
id: d5b382c0-4f16-49a7-a83e-06c7195be24f
name: iam_policy_attached
status: experimental
description: >-
  Base rule — correlation component and change accounting, never for direct alerting. Any successful
  attachment of a managed policy to a user, role or group. In an estate that manages permissions
  through IaC this fires continuously, which is why it is informational.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html
tags:
  - attack.persistence
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'AttachUserPolicy'
      - 'AttachRolePolicy'
      - 'AttachGroupPolicy'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: classify a customer-managed policy as administrative without
reading its document. The list is derived once, in §4, and until it is the rules under-report by the
number of home-grown administrative policies in the account.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> IAM is a **global service**: run these in `us-east-1`, where its events are recorded.

Run Query 1 first; it produces the grantee that Query 2 resolves.

#### Query 1 — Reconstruct: who granted what, to whom

```bash
REGION="us-east-1"   # IAM events are global-service events, recorded here
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in AttachUserPolicy AttachRolePolicy AttachGroupPolicy \
           DetachUserPolicy DetachRolePolicy DetachGroupPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # The grantee field name differs per event type, so all three are read.
      | ($r.userName // $r.roleName // $r.groupName // "-") as $grantee
      | (if $r.groupName then "GROUP" elif $r.roleName then "role" else "user" end) as $type
      | (.userIdentity.arn // "?") as $caller
      # Self-grant: the grantee name appears in the caller ARN. This is a field COMPARISON, which
      # Sigma cannot express — it exists only here and in the KQL.
      | (if ($caller | contains("/" + $grantee)) then "  *** SELF-GRANT ***" else "" end) as $self
      | "\(.eventTime)  \(.eventName)  \($caller)  -> \($type):\($grantee)  " +
        "policy=\($r.policyArn // "-")\($self)  ip=\(.sourceIPAddress)"'
done | sort
```

`*** SELF-GRANT ***` is the least ambiguous shape available in this use case and it is the one no
Sigma rule in the directory can produce. Count distinct grantees per caller within an hour as well —
three or more is the fan-out case, which matters when an actor is establishing access across several
identities rather than escalating one.

#### Query 2 — Resolve blast radius, which differs by principal type

```bash
GRANTEE="${1:?grantee name from Query 1}"
TYPE="${2:?user|role|group}"

case "$TYPE" in
  group)
    # A group grant reaches every CURRENT member — and every FUTURE one, with no further event.
    echo "=== Current members (future members inherit silently) ==="
    aws iam get-group --group-name "$GRANTEE" --query 'Users[].UserName' --output text 2>/dev/null \
      | tr '\t' '\n' | sed 's/^/  /'
    echo "=== Policies now attached to the group ==="
    aws iam list-attached-group-policies --group-name "$GRANTEE" \
      --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n' | sed 's/^/  /'
    ;;
  role)
    # For a role the blast radius is whoever can ASSUME it, which is the trust policy.
    echo "=== Who can assume this role — the real blast radius ==="
    aws iam get-role --role-name "$GRANTEE" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null \
    | jq -r '(if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
        | select(.Effect == "Allow")
        | "  principal=\(.Principal)  condition=\(.Condition // "none")"'
    echo "=== Policies now attached to the role ==="
    aws iam list-attached-role-policies --role-name "$GRANTEE" \
      --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n' | sed 's/^/  /'
    ;;
  user)
    aws iam list-attached-user-policies --user-name "$GRANTEE" \
      --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null | tr '\t' '\n' | sed 's/^/  /'
    aws iam list-groups-for-user --user-name "$GRANTEE" \
      --query 'Groups[].GroupName' --output text 2>/dev/null | tr '\t' '\n' | sed 's/^/  in group: /'
    ;;
esac
```

The three branches are genuinely different questions. For a user it is one identity. For a group it
is a membership list that will grow. For a role it is the trust policy — a role nobody can assume is
a much smaller problem than one assumable by an application or a whole account.

#### Query 3 — Derive the account's real administrative-policy list

```bash
# The rules ship with AWS-managed entries only. This is what makes them correct for THIS account:
# any customer-managed policy granting Allow on Action:"*" is administrative regardless of its name.
echo "=== Customer-managed policies granting Action:* ==="
aws iam list-policies --scope Local --only-attached \
  --query 'Policies[].[Arn,DefaultVersionId]' --output text 2>/dev/null \
| while IFS=$'\t' read -r ARN V; do
    [ -z "$ARN" ] && continue
    aws iam get-policy-version --policy-arn "$ARN" --version-id "$V" \
      --query 'PolicyVersion.Document' --output text 2>/dev/null \
    | python3 -c '
import sys, json, urllib.parse, os
raw = sys.stdin.read().strip()
if not raw: raise SystemExit(0)
# GetPolicyVersion RETURNS percent-encoded content; decode conditionally (authoring rule A4).
if raw.startswith("%"): raw = urllib.parse.unquote(raw)
stmts = json.loads(raw).get("Statement", [])
if isinstance(stmts, dict): stmts = [stmts]
for s in stmts:
    act = s.get("Action", []); act = act if isinstance(act, list) else [act]
    if s.get("Effect") == "Allow" and "*" in act:
        print("  " + os.environ["ARN"]); break
' ARN="$ARN"
  done

echo
echo "=== Add every line above to administrative_policies in the Sigma rule and to"
echo "    AdminPolicies in the KQL. Until then both under-report by exactly this many policies."
```

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?caller ARN from Query 1 required}"
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

Look for `CreatePolicy` or `CreatePolicyVersion` shortly **before** the attach. Author-then-attach by
one principal is the complete escalation in two calls, and the authoring half is covered in
`../iam.privilege-escalation.policy-version-overly-permissive/`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Detach first — it is one call and it removes the grant. Then deal with sessions, which detaching does
**not** address for a role.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows a
self-grant, or an administrative policy on a group, treat every affected principal as compromised
for the window. A group grant in particular keeps applying to members added after the event, so the
attachment is the thing to remove rather than the members to review.

#### Step 1 — Detach the policy

```bash
GRANTEE="${1:?grantee name from Query 1}"
TYPE="${2:?user|role|group}"
POLICY_ARN="${3:?policy ARN from Query 1}"

case "$TYPE" in
  user)  aws iam detach-user-policy  --user-name  "$GRANTEE" --policy-arn "$POLICY_ARN" ;;
  role)  aws iam detach-role-policy  --role-name  "$GRANTEE" --policy-arn "$POLICY_ARN" ;;
  group) aws iam detach-group-policy --group-name "$GRANTEE" --policy-arn "$POLICY_ARN" ;;
  *) echo "[FAIL] unknown principal type: $TYPE"; exit 1 ;;
esac && echo "[OK] $POLICY_ARN detached from $TYPE:$GRANTEE"

echo "[!] For a ROLE this does NOT affect sessions already issued — they keep the permissions"
echo "    until expiry. Step 2 is what revokes those."
```

#### Step 2 — Revoke sessions issued while the policy was attached

```bash
ROLE="${1:?role name — skip this step for users and groups}"

# Detaching changes what NEW sessions get. Existing session credentials were minted with the
# escalated permissions and remain valid until they expire.
cat <<JSON > /tmp/revoke-${ROLE}.json
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"}}}]}
JSON

echo "[!] Review /tmp/revoke-${ROLE}.json, then attach it:"
echo "    aws iam put-role-policy --role-name $ROLE \\"
echo "      --policy-name RevokeOlderSessions --policy-document file:///tmp/revoke-${ROLE}.json"
echo "[!] This denies EVERYTHING to sessions older than now. On a role running production"
echo "    workloads it will stop them, which is often correct and is never automatic."
```

For a **user**, the equivalent is deactivating access keys; for a **group**, there are no sessions
to revoke — the members' own sessions are what matter, and each member is handled as a user or a
role.

#### Step 3 — Contain the principal that made the change

```bash
PRINCIPAL="${1:?caller ARN from Query 1 required}"

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
    echo "[!] assumed role: $R — apply the same revoke-by-token-issue-time policy as Step 2."
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

#### Step 4 — Establish what the escalated principal did

```bash
GRANTEE="${1:?grantee name}"
START="${2:?attach timestamp from Query 1}"
END="${3:?detach timestamp from Step 1}"
REGION="us-east-1"

# For a GROUP, run this for each member from Query 2 rather than for the group name — a group is
# not a principal and never appears as a CloudTrail caller.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$GRANTEE" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --query 'Events[].[EventTime,EventName,EventSource]' --output text 2>/dev/null | sort
```

---

## 4. Eradication

### Remove Attacker Access

#### Derive the administrative-policy list and deploy it

Query 3 produces it. This is the eradication step that changes whether the detection works at all:
until the account's home-grown administrative policies are in the rule, the critical rule sees only
attachments of the three AWS-managed policies it ships with, and an attacker attaching a local
policy that grants `Action: "*"` produces a P2 at most.

#### Remove standing administrative attachments

The sweep in Query 3 uses `--only-attached` deliberately: an administrative policy attached to
nothing is a latent problem, but one attached to an application role is a live one. Every such
attachment is a place this technique does not need to happen because the access already exists.

#### Prefer group membership changes to policy attachments — and watch them too

Group-based permission management is correct practice and it moves the escalation to
`AddUserToGroup`, which is a different event this playbook does not cover. If the estate manages
permissions by group, that event needs its own rule; otherwise tightening `AttachGroupPolicy` simply
relocates the technique.

#### Deny administrative attachment outside a break-glass path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyAdministrativePolicyAttachment",
  "Effect": "Deny",
  "Action": ["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy"],
  "Resource": "*",
  "Condition": {
    "ArnLike": {"iam:PolicyARN": ["arn:aws:iam::aws:policy/AdministratorAccess",
                                  "arn:aws:iam::aws:policy/PowerUserAccess",
                                  "arn:aws:iam::aws:policy/IAMFullAccess"]},
    "ArnNotLike": {"aws:PrincipalARN": "arn:aws:iam::*:role/YourBreakGlassRole"}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. `YourBreakGlassRole` must
be a role that genuinely exists — an `ArnNotLike` against a non-existent role denies the action to
everyone including you. Note this uses `iam:PolicyARN`, which lets the denial name specific policies
rather than all attachment: extend the `ArnLike` list with the customer-managed policies Query 3
found, or the SCP has the same blind spot as the original rule. Test in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify the attachment is gone and no equivalent remains

```bash
GRANTEE="${1:?grantee name}"
TYPE="${2:?user|role|group}"
POLICY_ARN="${3:?policy ARN}"

case "$TYPE" in
  user)  LIST="$(aws iam list-attached-user-policies  --user-name  "$GRANTEE" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)" ;;
  role)  LIST="$(aws iam list-attached-role-policies  --role-name  "$GRANTEE" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)" ;;
  group) LIST="$(aws iam list-attached-group-policies --group-name "$GRANTEE" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)" ;;
esac

if printf '%s' "$LIST" | grep -q "$POLICY_ARN"; then
  echo "[FAIL] $POLICY_ARN is still attached to $TYPE:$GRANTEE"
else
  echo "[OK] $POLICY_ARN detached from $TYPE:$GRANTEE"
fi

# Detaching one administrative policy is not recovery if another is still attached.
for P in $LIST; do
  case "$P" in
    *AdministratorAccess*|*PowerUserAccess*|*IAMFullAccess*)
      echo "[FAIL] $TYPE:$GRANTEE still holds $P" ;;
  esac
done
echo "[OK] if no further FAIL printed, no known administrative policy remains attached"
```

#### Verify sessions were actually revoked

```bash
ROLE="${1:?role name}"

aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames' --output text 2>/dev/null \
| tr '\t' '\n' | grep -q 'RevokeOlderSessions' \
  && echo "[OK] session revocation policy is attached to $ROLE" \
  || echo "[FAIL] no RevokeOlderSessions policy — sessions issued before the detach are still valid"
```

This is the check most often skipped. A detached policy with live sessions still carrying its
permissions is the same situation as before containment, for as long as those sessions last.

#### Confirm the corrected detection fires

```bash
ROLE="${1:?a NON-PRODUCTION role name}"

# Exercise with PowerUserAccess rather than AdministratorAccess: it is administrative, it is NOT
# matched by the source rule's substring, and attaching it to a scratch role grants nothing of
# consequence. If the rule does not fire, the policy list is the thing that is wrong.
aws iam attach-role-policy --role-name "$ROLE" \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess \
  && echo "[OK] PowerUserAccess attached — expect the CRITICAL rule within 15 min"

sleep 60
aws iam detach-role-policy --role-name "$ROLE" \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess && echo "[OK] detached"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was the policy on the account's derived administrative list, or only on the AWS-managed default? | If the latter, a locally-authored administrative policy would have produced a P2 at most. |
| Was it a self-grant? | Caller and grantee being the same identity removes essentially every innocent reading, and it is the one verdict Sigma cannot produce. |
| Was the grantee a group? | Then the blast radius includes members added after the event, who inherit silently. |
| Were role sessions revoked, or only the policy detached? | Detaching changes new sessions only; existing ones keep the permissions until expiry. |
| Did the same principal author the policy shortly before attaching it? | That is the complete escalation in two calls and points at the sibling playbook. |
| Was the change made through SSO or CloudFormation? | The source pack excluded those on roles and not on users, so the answer determines whether it would have fired at all. |

### Recommended Guardrails

**Derive the administrative-policy list from documents, not names.** This single item decides whether
the detection works. `AdministratorAccess` as a substring is neither necessary nor sufficient.

**Filter the three attach paths identically.** Excluding SSO on roles and not on users creates a
blind spot that nobody chose and nobody documented.

**Rate group attachments above individual ones.** They reach members who do not exist yet, and no
event will ever be generated for those.

**Revoke sessions when detaching from a role.** Otherwise containment is nominal for the length of a
session, which on a long-lived role can be hours.

**Deny administrative attachment by SCP with `iam:PolicyARN`**, and keep that list in step with the
derived one. An SCP naming only the AWS-managed policies has exactly the blind spot this playbook
exists to correct.

### Technique Reference

**T1098.003 — Account Manipulation: Additional Cloud Roles.** Verified live at
https://attack.mitre.org/techniques/T1098/003/ on 2026-08-30. The five source rules carried **no**
MITRE mapping.

AWS references relied on throughout, all verified 2026-08-30:

- `AttachRolePolicy` and its per-principal siblings:
  https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html
- `AttachGroupPolicy`, whose grant reaches every member:
  https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachGroupPolicy.html

Service-wide verified behaviour shared by every `iam.*` playbook is in `../_ground-truth/iam.md`.

### Residual Risk

**The administrative list is never provably complete.** A customer-managed policy can be
administrative in effect — `iam:PassRole` plus `ec2:RunInstances`, or `iam:CreateAccessKey` on a
privileged user — without containing `Action: "*"` anywhere. Query 3 finds the wildcard case only,
and the rest is a materially harder problem than this playbook solves.

**Group membership changes are a different event.** Tightening `AttachGroupPolicy` moves the
technique to `AddUserToGroup`, which nothing here covers. In an estate that manages permissions by
group, that is where the equivalent detection needs to be.

**Permissions boundaries and SCPs can make an attachment inert.** A role with a permissions boundary
that excludes the attached policy's actions gains nothing, and this playbook will still rate it P0.
Checking the boundary is a manual triage step, and the event does not carry it.

**Sessions minted before containment are the real window.** Detaching is instant; a session issued a
minute earlier can carry the escalated permissions for its full duration. The revocation policy is
what closes that, and it is the step most likely to be skipped because it risks breaking a workload.
