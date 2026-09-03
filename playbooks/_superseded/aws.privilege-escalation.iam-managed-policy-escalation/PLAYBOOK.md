# IR Playbook: IAM Managed Policy Escalation — Escalating Every Attached Principal via `iam:SetDefaultPolicyVersion`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Privilege escalation / Account manipulation (a managed policy is rewritten or attached, escalating every principal that holds it) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | **High**, P0 where the promoted document is an unconditioned `*:*` or the attached policy is `AdministratorAccess`. One call escalates every principal the policy is attached to, which in a mature account is routinely dozens — the blast radius is a count, and the count is not in the event. The source rules rate these P2, which routes an account takeover to a queue nobody reads overnight |
| MITRE Tactics | Privilege Escalation, Persistence |
| MITRE Techniques | T1098.003 |
| Services in Scope | IAM, STS, CloudTrail, Organizations (SCP), Access Analyzer, plus every service reachable by the granted policy |

**What the technique does:** the actor takes one of two managed-policy routes. The first
rewrites a policy the target principals already hold: `iam:CreatePolicyVersion` adds a new
version to an existing customer-managed policy, and `iam:SetDefaultPolicyVersion` promotes
it — or `--set-as-default` on the create call does both at once, leaving no second event
to correlate against. The moment it is default, the new document applies to **every**
user, role and group that policy is attached to. The second route skips document authoring
entirely: `iam:AttachUserPolicy` (or the Role/Group variant) with the ARN of the AWS
managed `AdministratorAccess` policy. Neither needs the document to say `*:*` to be
terminal — `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:AddUserToGroup`,
`iam:UpdateAssumeRolePolicy`, or `iam:PassRole` with a compute-create action each reach
administrator in one further hop.

> The **inline** route to the same outcome (`PutUserPolicy` and siblings) escalates one
> named principal and leaves no version history, so its containment is evidence-first and
> irreversible. Separate playbook:
> `../../iam.privilege-escalation.inline-policy-grant/`.

**Why this is potent, and why the usual reflexes miss it.** The event names the *policy*,
not the principals. `requestParameters.policyArn` is the only identity in a
`SetDefaultPolicyVersion` event — who was actually escalated appears nowhere in
CloudTrail, and has to be retrieved separately with `iam:ListEntitiesForPolicy` while the
attachment still exists. A responder triaging from the event alone scopes the incident to
one policy ARN and misses that thirty roles just gained the permission. The second reflex
failure is temporal: `CreatePolicyVersion` on its own changes **nothing**, so an actor can
stage the escalating version hours or days before promoting it, and any detection keyed to
a short correlation window sees two unrelated routine events.

**Detection is the decoded document plus the promotion, not either event alone.**
`SetDefaultPolicyVersion` is what every legitimate policy rollback looks like, and
`CreatePolicyVersion` is inert until promoted, so neither is a signal by itself — the
source rules alert P2 on the bare `SetDefaultPolicyVersion` name, which fires on routine
rollbacks and gets muted (§2). The signal is an Allow statement carrying an escalation
primitive in the **decoded** document, and either `isDefaultVersion: true` on the create or
a matching promotion by the same principal on the same ARN.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing IAM **management** events. IAM is **global**:
  events are recorded in **`us-east-1`** regardless of where the caller sat, so every
  `lookup-events` call below pins that region
- `CreatePolicyVersion` carries `requestParameters.policyArn` and `.policyDocument`, and
  **nests** its response: `responseElements.policyVersion.versionId` and
  `.isDefaultVersion`. The flat `responseElements.versionId` is `null` on every event.
  **`isDefaultVersion: true` means the version went live on creation** and no promotion
  event is coming — a sequence-only detection misses it
- `SetDefaultPolicyVersion` carries `requestParameters.policyArn` and `.versionId` and
  names **no principal**. Who was escalated comes from `iam:ListEntitiesForPolicy`
- `Attach*Policy` carry `requestParameters.policyArn` and `.userName`/`.roleName`/`.groupName`
- `requestParameters.policyDocument` is **raw JSON**, in whatever whitespace the client
  sent — commonly pretty-printed from `--policy-document file://…`. **Do not decode it.**
  Percent-encoding (RFC 3986) applies to what IAM *returns*: `responseElements` and the
  `Get*Policy` APIs, which the CLI and boto3 decode for you
- A **record of which customer-managed policies are attached to more than five principals**,
  refreshed on a schedule. This is the pre-computed blast radius, and it is the difference
  between scoping the incident in seconds and scoping it after the attachment is gone

**Alerting (must be pre-configured)**
- **A policy version granting unconditioned `Action:*` on `Resource:*` becoming the default → P0**
- **`AdministratorAccess` or `IAMFullAccess` attached to any principal → P0**
- **A policy version created whose decoded document Allows an escalation primitive → P1**
- **`CreatePolicyVersion` followed by `SetDefaultPolicyVersion` on the same policy ARN by the same principal within 15 minutes → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation and specifically not the principal that made the change
- `jq`; `python3` and the kit's `tools/decode_policy_documents.py`
- The list of role ARNs legitimately permitted to write IAM policy, and the last known
  default `VersionId` for every customer-managed policy — without it, "roll back to
  known-good" has no target

**Known IOC Baselines**
- Which principals may call `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion` /
  `iam:Attach*Policy` at all — in most accounts one IaC deployment role and one
  break-glass role, everything else an incident
- Your own 12-digit account ID and every account ID in the organisation
- Which policies are AWS managed (`arn:aws:iam::aws:policy/...`) versus customer managed
  (`arn:aws:iam::<account>:policy/...`) — only the latter can have versions created

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | A policy version granting unconditioned `Action:*` on `Resource:*` becomes the default — via `SetDefaultPolicyVersion` or `isDefaultVersion: true` on create | CloudTrail (management) | T1098.003 |
| P0 | `Attach*Policy` with `policyArn` ending `:policy/AdministratorAccess` or `:policy/IAMFullAccess` | CloudTrail (management) | T1098.003 |
| P1 | `CreatePolicyVersion` whose decoded document Allows an escalation primitive (`CreateAccessKey`, `CreateLoginProfile`, `PassRole`, `AddUserToGroup`, `UpdateAssumeRolePolicy`, any `Attach*Policy`/`Put*Policy`) | CloudTrail (management) | T1098.003 |
| P1 | Ordered sequence `CreatePolicyVersion` → `SetDefaultPolicyVersion` on one `policyArn` by one principal within 15 minutes | CloudTrail (management) | T1098.003 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DeletePolicyVersion` immediately preceding `CreatePolicyVersion` on the same ARN — the actor clearing the five-version cap | CloudTrail (management) | T1098.003 |
| P2 | `SetDefaultPolicyVersion` promoting a version created more than 24 hours earlier — a staged escalation outside any correlation window | CloudTrail (management) | T1098.003 |
| P3 | Any `CreatePolicyVersion` / `Attach*Policy` outside the change window by an allowlisted pipeline role | CloudTrail (management) | T1098.003 |

### Detection Rule Quality Notes

The source rules alert on an event that is indistinguishable from a routine rollback,
match a policy ARN by an unanchored term, and build a correlation whose two stages overlap.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `SetDefaultPolicyVersion` alerts P2 on a bare event-name match with `threshold: 0.0` | This is exactly what a legitimate policy rollback looks like, so the rule fires on routine operations and is muted within a week — taking the escalation signal with it. It also never inspects *which* version is being promoted | Demote to a `low` base rule. Alert on the ordered `CreatePolicyVersion` → `SetDefaultPolicyVersion` sequence grouped by principal **and** policy ARN |
| `requestParameters.policyArn:AdministratorAccess` is an unanchored term match | Also matches `AdministratorAccess-Amplify` and `AdministratorAccess-AWSElasticBeanstalk` — narrow service policies that are routine wherever those services run, so the block fires on benign attaches | Anchor with `\|endswith: ':policy/AdministratorAccess'`; add `IAMFullAccess`, which grants the whole IAM surface without the word Administrator in its name |
| The `Policy Escalation` FLOW combines internal ID 49 (`Privileged API Calls`, twelve event names) with 33 (`Admin Policy Attached`, a strict subset of those names) at `timeframeMs: 0` | A single `AttachUserPolicy` of `AdministratorAccess` satisfies both stages at once, so the flow fires on exactly what stage 2 already caught and adds nothing | Correlate stages that are genuinely distinct and genuinely ordered — `CreatePolicyVersion` → `SetDefaultPolicyVersion` is the real two-step |
| `CreatePolicyVersion` regex `\x22Effect\x22:[ ]?\x22Allow\x22` allows **zero-or-one space, on one line** | `requestParameters.policyDocument` is raw JSON in the client's own whitespace, and the ordinary `--policy-document file://policy.json` submits it pretty-printed across newlines. The regex matches only compact single-line documents, so it misses the normal case. AWS's own parameter pattern admits tab, LF and CR, which is the giveaway | Match tokens, not punctuation-with-assumed-spacing; use a `\s*`-tolerant regex where punctuation is unavoidable. Do structural checks by parsing |
| Nothing matches `"Action":"iam:*"`, a `NotAction` grant, or the one-call `--set-as-default` form | `iam:*` is full IAM control and contains none of the named primitives; `NotAction` grants everything except; and `create-policy-version --set-as-default` emits **no** `SetDefaultPolicyVersion` event, so the sequence correlation never sees the more natural one-call attack | Sibling blocks for `"iam:*"`/`"sts:*"` and `NotAction`; a dedicated rule on `requestParameters.setAsDefault: true` |
| No `errorCode` filter on the P2 rules | A principal probing `CreatePolicyVersion` and collecting `AccessDenied` fires the identical P2 as a completed escalation. A sibling alert in the same source set uses `NOT _exists_:errorCode`, so the idiom was known and not applied here | Success path filtered to `errorCode: null`; denials handled by the shared volume correlation in the inline-route sibling |
| `AttachRolePolicy` excludes `userIdentity.invokedBy` cloudformation/sso; the User and Group siblings do not | Inconsistent, and the exclusion is itself a blind spot — escalation performed through a CloudFormation stack carries `invokedBy: cloudformation.amazonaws.com` and is dropped entirely | Do not exclude by `invokedBy`. Filter on the submitting *principal*, which CloudFormation preserves, not the service that relayed the call |
| `isDefaultVersion` is never read | A `CreatePolicyVersion` with `--set-as-default` produces no `SetDefaultPolicyVersion` event at all. Any detection built only on the sequence misses the single-call form completely | Read `responseElements.policyVersion.isDefaultVersion`; alert the escalating document in its own right, not only via the correlation |

**Recommended detection — an administrator-equivalent managed policy attached.**

```yaml
# IAM Privilege Escalation via Managed Policy (T1098.003)
#
# The managed route differs from the inline one in blast radius and in reversibility.
# A new default version of a customer-managed policy applies at once to EVERY principal
# that policy is attached to, so one call can escalate dozens of identities; and because
# managed policies ARE versioned, the prior document stays retrievable, which the inline
# route cannot offer. Both facts change the response, which is why this ships separately
# from ../../iam.privilege-escalation.inline-policy-grant/.
#
# Defects corrected here:
#  - `SetDefaultPolicyVersion` alerted P2 on a bare event-name match. That is what every
#    legitimate policy rollback looks like, so it fires on routine work and gets muted.
#    Demoted to a base rule; the ORDERED sequence is what alerts.
#  - `requestParameters.policyArn:AdministratorAccess` was an unanchored term match,
#    which also matches AdministratorAccess-Amplify and AdministratorAccess-AWSElasticBeanstalk
#    — narrow service policies routine wherever those services run. Anchored with |endswith.
#  - The CreatePolicyVersion document regex allowed zero-or-one space on a single line
#    (`\x22Effect\x22:[ ]?\x22Allow\x22`). `requestParameters.policyDocument` is RAW
#    JSON in whatever whitespace the client sent, and `--policy-document file://p.json`
#    is pretty-printed across newlines — so the regex misses those entirely. Percent-
#    encoding is a RESPONSE property (`responseElements`, the Get*Policy APIs); do not
#    decode request parameters. See `detection_note_t1098_003.md`.
title: Administrator-equivalent managed policy attached to a principal
id: 912af54e-62ea-44de-9742-6d00cfca791f
name: iam_admin_managed_policy_attached
status: experimental
description: >-
  An AWS managed policy conferring full administrative or full IAM control was attached
  to a user, role or group. Effective immediately and account-wide.
references:
  - https://attack.mitre.org/techniques/T1098/003/                      # retrieved 2026-08-27
  - https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html  # retrieved 2026-08-27
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
  admin_policy:
    requestParameters.policyArn|endswith:
      - ':policy/AdministratorAccess'
      - ':policy/IAMFullAccess'
      - ':policy/PowerUserAccess'
  success:
    errorCode: null
  condition: selection and admin_policy and success
falsepositives:
  - Initial account bootstrap and break-glass role provisioning. Both should be rare,
    scheduled, and attributable to a named change.
  - PowerUserAccess is not administrator-equivalent on its own — it withholds IAM. It is
    included because it is a common staging point; drop it if it is your standard
    developer grant.
level: high
---
# Unlike the inline sibling, the wildcard and named-primitive cases share ONE rule at
# `high` here. An inline `*:*` escalates one principal; a managed `*:*` escalates every
# principal the policy is attached to, so the weaker textual match still warrants the
# higher level.
title: IAM managed policy version created granting escalation or unrestricted action
id: e987be83-b7d4-4421-b019-1b68ac865365
name: iam_managed_version_escalation
status: experimental
description: >-
  A new version of a customer-managed policy was created whose document Allows a
  privilege-escalation primitive or an unrestricted action. If promoted to default it
  applies to every principal the policy is attached to.
references:
  - https://attack.mitre.org/techniques/T1098/003/                      # retrieved 2026-08-27
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html  # retrieved 2026-08-27
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
    eventName: 'CreatePolicyVersion'
  allow_effect:
    requestParameters.policyDocument|contains: 'Allow'
  # Bare alphanumerics — identical in raw JSON and percent-encoded form.
  escalation_action:
    requestParameters.policyDocument|contains:
      - 'CreateAccessKey'
      - 'CreateLoginProfile'
      - 'UpdateLoginProfile'
      - 'AttachUserPolicy'
      - 'AttachRolePolicy'
      - 'AttachGroupPolicy'
      - 'PutUserPolicy'
      - 'PutRolePolicy'
      - 'PutGroupPolicy'
      - 'CreatePolicyVersion'
      - 'SetDefaultPolicyVersion'
      - 'AddUserToGroup'
      - 'UpdateAssumeRolePolicy'
      - 'AdministratorAccess'
  # \s* spans the newlines and indentation of a pretty-printed document — the real
  # request-side hazard. The optional [ handles "Action": [ "*" ].
  wildcard_action:
    requestParameters.policyDocument|re: '"Action"\s*:\s*(\[\s*)?"\*"'
  # A service wildcard over IAM or STS confers every named primitive at once while
  # containing none of their names.
  wildcard_service:
    requestParameters.policyDocument|contains:
      - '"iam:*"'
      - '"sts:*"'
  # NotAction Allows everything EXCEPT what it lists — administrator by omission.
  not_action:
    requestParameters.policyDocument|contains: 'NotAction'
  success:
    errorCode: null
  condition: selection and success and allow_effect and (escalation_action or wildcard_action or wildcard_service or not_action)
falsepositives:
  - A guardrail version that Denies these actions while Allowing something else in the
    same document — Allow and the action name are matched independently. Decode first.
  - '`iam:PassRole` is deliberately excluded from the primitive list: it appears in a
    large fraction of legitimate IaC-managed policies and would dominate alert volume at
    this level. The decoded path in Query 3 of the playbook catches it.'
  - CreatePolicyVersion without --set-as-default changes nothing until the version is
    promoted. Corroborate against the sequence correlation below before escalating.
level: high
---
title: IAM CreatePolicyVersion
id: 3523562f-94ec-4c98-bad9-c48186f7472e
name: iam_create_policy_version
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html  # retrieved 2026-08-27
tags:
  - attack.privilege-escalation
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
level: low
---
title: IAM SetDefaultPolicyVersion
id: f58a9365-6c49-4bf6-ae55-759d847b72f7
name: iam_set_default_policy_version
status: experimental
description: Base rule — sequence component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_SetDefaultPolicyVersion.html  # retrieved 2026-08-27
tags:
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
  condition: selection and success
level: low
---
# The two-step managed escalation. Neither half is suspicious alone: CreatePolicyVersion
# without --set-as-default changes nothing, and SetDefaultPolicyVersion is what every
# legitimate rollback looks like. The original rule alerted P2 on the latter by itself,
# which is why it fires on rollbacks. The SEQUENCE by one principal against one policy
# ARN is the technique.
title: IAM policy version created then promoted to default by the same principal
id: 848d5f5c-3118-41ab-975c-ac2a13ae5ce0
status: experimental
description: >-
  A new version of a managed policy was created and then made the default version by the
  same principal on the same policy. The new document applies at once to every principal
  that policy is already attached to.
references:
  - https://attack.mitre.org/techniques/T1098/003/                      # retrieved 2026-08-27
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.003
correlation:
  type: temporal_ordered
  rules:
    - iam_create_policy_version
    - iam_set_default_policy_version
  group-by:
    - userIdentity.arn
    - requestParameters.policyArn
  timespan: 15m
level: high

---
# The ONE-CALL form. `aws iam create-policy-version --set-as-default` emits a single
# CreatePolicyVersion event with requestParameters.setAsDefault true and NO
# SetDefaultPolicyVersion event at all — so the sequence correlation below never fires on
# it. It is also the more natural attacker path, being one call instead of two.
title: IAM policy version created and promoted to default in one call
id: 6d2a4b18-90ce-4f77-b3a1-5e0c72d98af3
status: experimental
description: >-
  A new managed-policy version was created with set-as-default in a single call, taking
  effect immediately on every principal the policy is attached to, with no separate
  promotion event to correlate against.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html  # retrieved 2026-08-27
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
    eventName: 'CreatePolicyVersion'
  set_as_default:
    requestParameters.setAsDefault: true
  success:
    errorCode: null
  condition: selection and set_as_default and success
falsepositives:
  - Your IaC pipeline rolling a managed policy forward. This is the normal deployment
    shape, so allowlist the pipeline role explicitly rather than lowering the level.
level: medium
```

Reproduced byte-for-byte from the first rule document of
`detections/sigma_t1098_003.yml` (the file's leading comment block, which records what the
original rules got wrong, is not repeated — §2 above says the same in prose). Four further
documents ship in that file: the escalating-policy-version rule (`high`), the
`CreatePolicyVersion` → `SetDefaultPolicyVersion` sequence correlation (`high`), and its
two base rules (`low`). **Deploy the file, not this excerpt.**

**What these rules structurally cannot do.** They match substrings of a document and names
of events. They cannot tell you *who was escalated* — that is `iam:ListEntitiesForPolicy`,
Query 2 below — and they cannot bridge a staged escalation where the version is created
days before it is promoted, because a correlation needs a window and a patient actor will
exceed it. The `SetDefaultPolicyVersion` base rule is deployed at `low` precisely so that
promotion of an old version is still *searchable* even when nothing alerts on it. Full
reasoning is in `detections/detection_note_t1098_003.md`.

---

### Key Investigation Queries

> **IAM is a global service — its CloudTrail events land in `us-east-1` only.** Running these against the caller's own region returns zero. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: which policy changed, by whom, and did it go live

```bash
REGION="us-east-1"; WINDOW="7 days ago"     # wider than the inline route: versions are staged

for EV in CreatePolicyVersion SetDefaultPolicyVersion DeletePolicyVersion \
          AttachUserPolicy AttachRolePolicy AttachGroupPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "iam.amazonaws.com") |
    (.userIdentity.arn // "") as $arn | ($arn | split("/")) as $p |
    # assumed-role ARN: role name is the 2nd "/" segment, the LAST is the SESSION name.
    # IAM-user ARN: the name IS the last segment. One idiom does not serve both.
    {time: .eventTime, event: .eventName,
     caller_arn: $arn,
     caller_name: (if ($arn | test(":assumed-role/")) then $p[1] else $p[-1] end),
     access_key: .userIdentity.accessKeyId,           # feeds ACCESS_KEY_ID in Query 4
     policy_arn: .requestParameters.policyArn,        # feeds POLICY_ARN in Queries 2 and 3
     grantee: (.requestParameters.userName // .requestParameters.roleName
               // .requestParameters.groupName),      # Attach* only; null on version calls
     version_id: (.responseElements.policyVersion.versionId    # NESTED — the flat path
                  // .requestParameters.versionId),            # is null on every event
     live_on_create: .responseElements.policyVersion.isDefaultVersion,
     invoked_by: .userIdentity.invokedBy,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Read it per `policy_arn`, not per row. **`live_on_create: true` means the version went
live on the create call and there is no promotion event to look for** — do not conclude
the version is dormant because no `SetDefaultPolicyVersion` appears. A `CreatePolicyVersion`
and a later `SetDefaultPolicyVersion` sharing a `policy_arn` is the two-call form, and the
gap between them may be days. A `DeletePolicyVersion` immediately before a create is the
actor clearing the five-version cap — note it, because the deleted document is gone and
your version history is incomplete from that point. `invoked_by` of
`cloudformation.amazonaws.com` does **not** exonerate: `caller_arn` is still the submitting
principal. Record `caller_arn`, `access_key`, `policy_arn`, `version_id` and the change
`time`.

#### Query 2 — Blast radius: who was actually escalated

The number this route needs and the inline route does not. It is not in the event, and it
disappears the moment anyone detaches the policy — **run it before containment.**

```bash
POLICY_ARN="<policy-arn-from-Query-1>"

aws iam list-entities-for-policy --policy-arn "$POLICY_ARN" --output json \
  | jq '{users:   [.PolicyUsers[].UserName],
         roles:   [.PolicyRoles[].RoleName],
         groups:  [.PolicyGroups[].GroupName],
         total:   ([.PolicyUsers, .PolicyRoles, .PolicyGroups] | map(length) | add)}' \
  | tee /tmp/ir-blast-radius.json

TOTAL=$(jq -r '.total' /tmp/ir-blast-radius.json)
echo "[!] $TOTAL principal(s) hold $POLICY_ARN and received the promoted document"
[ "$TOTAL" -gt 5 ] && echo "[!] Blast radius exceeds five principals — treat as an account-wide event, not a single-principal one"
```

Every name in that output is a principal whose effective permissions changed, whether or
not it appears anywhere else in this incident. Groups expand further — a group holding the
policy escalates every user in it, so resolve group membership with
`aws iam get-group --group-name <g>` before declaring the scope closed. Preserve
`/tmp/ir-blast-radius.json`; after rollback the attachment list still exists but the
*evidence of who was exposed and when* does not.

#### Query 3 — Inspect: decode the policy versions and read them statement by statement

`decode_policy_documents.py` decodes unconditionally — a no-op on raw JSON, resolving the
raw `Document` returned by the API — then evaluates each statement in isolation,
answering the questions no substring match can. It carries the scalar-or-array shape guards and is shared with the
inline-route playbook.

```bash
POLICY_ARN="<policy-arn-from-Query-1>"
KIT="<path-to-playbook-authoring-kit>"

# The live versions, straight from IAM. get-policy-version returns the document ALREADY
# DECODED by the CLI, so it is re-wrapped here to match the tool's input shape.
for V in $(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
             --query 'Versions[].VersionId' --output text); do
  aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$V" --output json \
    | jq -c --arg v "$V" --arg a "$POLICY_ARN" \
        '{time: (.PolicyVersion.CreateDate // "unknown"),
          caller: "-", grantee: $a, policy_name: ("version " + $v + (if .PolicyVersion.IsDefaultVersion then " [DEFAULT]" else "" end)),
          doc: (.PolicyVersion.Document | tojson)}'
done | python3 "$KIT/tools/decode_policy_documents.py"
```

The version marked `[DEFAULT]` is the one in force. `[!] FULL ADMIN` on it is terminal for
every principal Query 2 listed. `[!] PRIMITIVE` names the actions granted, and that list is
the eradication work-list. A `[!]` on a non-default version is a staged escalation that has
not been promoted yet — still an incident, and the version should be deleted. If the
version count is already five, an earlier document was deleted to make room and is
unrecoverable; say so in the report rather than presenting the surviving history as
complete.

#### Query 4 — Session reconstruction: what the principal did after the change

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
CHANGE_TIME="<time-from-Query-1>"         # ISO8601, the moment the version went default

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg t "$CHANGE_TIME" '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     phase: (if .eventTime > $t then "AFTER-CHANGE" else "before" end),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

The **"was it used"** pivot. Every `AFTER-CHANGE` row succeeding on a call that would have
been denied before is the escalation being exercised; `CreateAccessKey`,
`CreateLoginProfile`, `CreateUser`, `CreateRole`, `UpdateAssumeRolePolicy` and `AssumeRole`
into a new role outlive the rollback you are about to perform. IAM management events are
complete, so an empty `AFTER-CHANGE` set is real evidence *this credential* did not use it
— but this route escalated everyone in Query 2's list, and **any of them** could have
exercised it. Re-run for the access keys of the highest-privilege principals on that list
before closing.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Rollback here is clean and it is fast: managed policies are versioned, so a single
`set-default-policy-version` reverses the grant for every affected principal at once, and
the pre-incident document is still retrievable. That is the advantage this route has over
its inline sibling — and the reason the ordering differs. **Capture the blast radius before
you roll back**, because rollback does not tell you who was exposed, and detaching the
policy destroys the list entirely.

> Run every command under the **break-glass responder credentials** from §1 — not under
> any principal being contained, and not under the principal that made the change.

#### Step 1 — Capture the blast radius and every version, then roll back

```bash
POLICY_ARN="<policy-arn-from-Query-1>"
GOOD_VERSION="<known-good-version-id>"        # the default before the incident
EVIDENCE="/tmp/ir-iam-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$EVIDENCE"

# 1. Who holds it — this list is gone the moment anyone detaches the policy.
aws iam list-entities-for-policy --policy-arn "$POLICY_ARN" --output json \
  > "$EVIDENCE/blast-radius.json" && echo "[OK] Blast radius captured"

# 2. Every surviving version. If there are five, one was deleted to make room and that
#    document is unrecoverable — note it in the report.
for V in $(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
             --query 'Versions[].VersionId' --output text); do
  aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$V" \
    --output json > "$EVIDENCE/version-${V}.json"
done
NVER=$(ls "$EVIDENCE"/version-*.json 2>/dev/null | wc -l | tr -d ' ')
echo "[OK] Captured $NVER policy version(s)"
[ "$NVER" -ge 5 ] && echo "[!] Version cap reached — an earlier document was deleted to make room and cannot be recovered"

# 3. Roll the default back. API SetDefaultPolicyVersion -> CLI set-default-policy-version.
aws iam set-default-policy-version --policy-arn "$POLICY_ARN" --version-id "$GOOD_VERSION" && \
  echo "[OK] Rolled $POLICY_ARN default back to $GOOD_VERSION — effective immediately for all attached principals"
```

> Roll back; do not delete the policy. It is attached to principals that still need it,
> and deleting it detaches them all — an availability incident on top of a security one.
> Delete the *malicious version* only after the rollback is verified, and only once the
> version JSON is preserved outside the account.

#### Step 2 — Detach any administrator-equivalent managed policy

```bash
GRANTEE="<grantee-from-Query-1>"
KIND="<user|role|group>"                       # from Query 1's event name
ADMIN_ARN="<policy-arn-from-Query-1>"

aws iam detach-${KIND}-policy --${KIND}-name "$GRANTEE" --policy-arn "$ADMIN_ARN" && \
  echo "[OK] Detached $ADMIN_ARN from ${KIND} $GRANTEE — effective immediately"
```

#### Step 3 — Neutralise credentials minted during the window

These survive the rollback, and they are the actual persistence.

```bash
REGION="us-east-1"
CHANGE_TIME="<time-from-Query-1>"

# Read BOTH names from responseElements. requestParameters.userName is OPTIONAL — when
# omitted the key is minted for the CALLER, the ordinary persistence move, and keying on
# it yields "null:AKIA…", a failed disable, and a false [OK] in Recovery.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time "$CHANGE_TIME" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) |
    "\(.responseElements.accessKey.userName):\(.responseElements.accessKey.accessKeyId)"' \
  | tee /tmp/ir-window-keys.txt

# Quote into a variable first — a bare <placeholder> in a for-list is a shell syntax
# error, since < and > are redirection metacharacters.
NEW_KEYS="$(tr '\n' ' ' < /tmp/ir-window-keys.txt)"
for PAIR in $NEW_KEYS; do
  U="${PAIR%%:*}"; K="${PAIR##*:}"
  { [ -z "$U" ] || [ -z "$K" ]; } && continue
  aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive && \
    echo "[OK] Disabled key $K for user $U"
done
```

> Disable, do not delete. An inactive key stays enumerable and keeps its creation
> metadata; deleting it removes the evidence of what the attacker built. Cross-check the
> usernames against `blast-radius.json` — a key minted by a principal on that list is the
> escalation being exercised, not a coincidence.

#### Step 4 — Contain the principal that made the change

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REVOKE_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}'
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:CreatePolicyVersion","iam:SetDefaultPolicyVersion","iam:DeletePolicyVersion","iam:AttachUserPolicy","iam:AttachRolePolicy","iam:AttachGroupPolicy","iam:PutUserPolicy","iam:PutRolePolicy","iam:PutGroupPolicy","iam:CreateAccessKey","iam:CreateLoginProfile","iam:UpdateAssumeRolePolicy","iam:AddUserToGroup"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')        # user ARN: name = LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyIAMWrite" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further IAM writes by user $U"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')         # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document "$REVOKE_DOC" && echo "[OK] Revoked sessions for role $R"
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyIAMWrite" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further IAM writes by role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

> `aws:TokenIssueTime` denies only tokens issued **before** the cutoff — a credential
> re-fetched from IMDS afterwards is not denied. It kills currently-leaked session tokens;
> it does not gate the role or stop fresh theft from a still-compromised host.

---

## 4. Eradication

### Remove Attacker Access

#### Delete the malicious version, once the rollback is verified

```bash
POLICY_ARN="<policy-arn-from-Query-1>"
BAD_VERSION="<version-id-from-Query-1>"

# A version cannot be deleted while it is the default — Step 1's rollback must land first.
LIVE=$(aws iam get-policy --policy-arn "$POLICY_ARN" --query 'Policy.DefaultVersionId' --output text)
if [ "$LIVE" = "$BAD_VERSION" ]; then
  echo "[FAIL] $BAD_VERSION is still the default — re-run Containment Step 1 before deleting"
else
  aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$BAD_VERSION" && \
    echo "[OK] Deleted malicious version $BAD_VERSION (JSON preserved in \$EVIDENCE)"
fi
```

#### Work the blast radius, not the event

Every principal in `blast-radius.json` held the escalated permission for the whole window.
For each, and especially for groups — whose members inherit it — check Query 4 for keys,
login profiles, new roles, or trust-policy changes created while it was in force. An actor
who escalated thirty roles only needs one of them to have established persistence.

#### Remove the persistence the escalation established

- **Access keys** created after `CHANGE_TIME` — disabled in Step 3, delete once documented
- **Login profiles** — `aws iam delete-login-profile --user-name <user>` for any created
  in the window
- **New roles** whose trust policy names an outside account — a full re-entry path, and
  the role-trust-backdoor playbook rather than this one
- **Inline policies** written during the window — if Query 4 shows `Put*Policy`, work
  `../../iam.privilege-escalation.inline-policy-grant/` before closing

#### Right-size the permission and remove emergency policies

```bash
echo "[i] Identify which policy on the actor permits iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion:"
aws iam list-attached-role-policies --role-name "<actor-role-name>" --output table 2>/dev/null
aws iam list-role-policies          --role-name "<actor-role-name>" --output table 2>/dev/null

for RN in "<actor-role-name>"; do
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyRevokeSessions" 2>/dev/null
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyDenyIAMWrite"   2>/dev/null
done
# Step 4 uses put-user-policy when the actor was an IAM USER — that path needs the
# user-side removal, which delete-role-policy does not cover.
aws iam delete-user-policy --user-name "<actor-user-name>" --policy-name "EmergencyDenyIAMWrite" 2>/dev/null
# D-0: assert, do not announce. delete-*-policy exits 0 whether or not anything was
# there, so re-list and confirm absence; a listing failure is INCONCLUSIVE, never [OK].
LEFT=0; UNK=0
for RN in "<grantor-role-name>" "<grantee-role-name>"; do
  L=$(aws iam list-role-policies --role-name "$RN" --query 'PolicyNames[]' --output text 2>/dev/null)
  if [ -z "$L" ] && ! aws iam get-role --role-name "$RN" >/dev/null 2>&1; then UNK=$((UNK+1)); continue; fi
  printf '%s' "$L" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] $RN still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
done
U=$(aws iam list-user-policies --user-name "<grantor-user-name>" --query 'PolicyNames[]' --output text 2>/dev/null)
printf '%s' "$U" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] grantor user still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
[ "$UNK" -gt 0 ] && echo "[!] $UNK principal(s) could not be listed — INCONCLUSIVE, not clean"
{ [ "$LEFT" -eq 0 ] && [ "$UNK" -eq 0 ]; } && echo "[OK] No Emergency* policy remains on any contained principal"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the default version is known-good and the malicious version is gone

```bash
POLICY_ARN="<policy-arn-from-Query-1>"
GOOD_VERSION="<known-good-version-id>"
BAD_VERSION="<version-id-from-Query-1>"

LIVE=$(aws iam get-policy --policy-arn "$POLICY_ARN" --query 'Policy.DefaultVersionId' --output text)
[ "$LIVE" = "$GOOD_VERSION" ] && echo "[OK] $POLICY_ARN default is $LIVE (known-good)" \
                             || echo "[FAIL] $POLICY_ARN default is $LIVE, expected $GOOD_VERSION"

REMAIN=$(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
           --query "Versions[?VersionId=='$BAD_VERSION'].VersionId" --output text)
[ -z "$REMAIN" ] && echo "[OK] Malicious version $BAD_VERSION no longer exists" \
                 || echo "[FAIL] $BAD_VERSION is still present on $POLICY_ARN"
```

#### Verify the admin policy is detached

```bash
ADMIN_ARN="<policy-arn-from-Query-1>"
GRANTEE="<grantee-from-Query-1>"

HOLDERS=$(aws iam list-entities-for-policy --policy-arn "$ADMIN_ARN" --output json 2>/dev/null \
  | jq -r --arg g "$GRANTEE" \
      '[.PolicyUsers[].UserName, .PolicyRoles[].RoleName, .PolicyGroups[].GroupName]
       | map(select(. == $g)) | length')
[ "${HOLDERS:-0}" -eq 0 ] && echo "[OK] $GRANTEE no longer holds $ADMIN_ARN" \
                          || echo "[FAIL] $GRANTEE still holds $ADMIN_ARN"
```

#### Verify no access key created during the window is still active

```bash
REGION="us-east-1"; CHANGE_TIME="<time-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time "$CHANGE_TIME" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) |
         "\(.responseElements.accessKey.userName) \(.responseElements.accessKey.accessKeyId)"' \
  > /tmp/ir-window-keys-verify.txt

STILL_ACTIVE=0
while read -r U K; do
  [ -z "$U" ] && continue
  S=$(aws iam list-access-keys --user-name "$U" \
        --query "AccessKeyMetadata[?AccessKeyId=='$K'].Status" --output text 2>/dev/null)
  [ "$S" = "Active" ] && { echo "[FAIL] key $K on $U created after $CHANGE_TIME is still Active"; STILL_ACTIVE=$((STILL_ACTIVE+1)); }
done < /tmp/ir-window-keys-verify.txt

[ "$STILL_ACTIVE" -eq 0 ] && echo "[OK] No key created after $CHANGE_TIME remains Active" \
                          || echo "[FAIL] $STILL_ACTIVE window-created key(s) still Active"
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rules MUST fire on:"
echo "  1. eventSource=iam.amazonaws.com  eventName=AttachRolePolicy  errorCode absent"
echo "     requestParameters.policyArn = arn:aws:iam::aws:policy/AdministratorAccess"
echo "     -> iam_admin_managed_policy_attached, level high"
echo "  2. eventName=CreatePolicyVersion  errorCode absent, document in BOTH encodings:"
echo '     raw     {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}'
echo '     encoded %7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22iam%3APassRole%22%7D%5D%7D'
echo "     -> iam_managed_version_escalation, level high, on BOTH encodings"
echo "  3. CreatePolicyVersion then SetDefaultPolicyVersion, same principal, same"
echo "     policyArn, 5 minutes apart -> the sequence correlation, level high"
echo
echo "The rules MUST NOT fire on:"
echo "  1. AttachRolePolicy with policyArn .../AdministratorAccess-Amplify"
echo "     -> |endswith ':policy/AdministratorAccess' does not match the -Amplify suffix"
echo "  2. SetDefaultPolicyVersion alone with no preceding CreatePolicyVersion by the same"
echo "     principal on the same ARN — a routine rollback, base rule only, level low"
echo "  3. A CreatePolicyVersion whose document only Denies — allow_effect does not match"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could rewrite a managed policy that many identities held | `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion` held outside the IAM-administration pipeline, with no permissions boundary on the principals holding the policy |
| One call escalated many principals at once | High-fan-out managed policies were not tracked, so nobody knew the blast radius of a change to any given policy ARN |
| The change was not detected | The deployed rule alerted on `SetDefaultPolicyVersion` by name — indistinguishable from routine rollback — and the document regex searched one of the two formats CloudTrail stores |
| A staged escalation would have been missed entirely | Detection relied on a short correlation window; `CreatePolicyVersion` is inert and can be staged days ahead of promotion |
| The single-call form was invisible | `responseElements.policyVersion.isDefaultVersion` was never read, so `--set-as-default` produced no correlatable sequence and no alert |
| Version history was incomplete at response time | The five-version cap forces `DeletePolicyVersion` before a sixth, and no out-of-account snapshot of policy versions existed |

### Recommended Guardrails

**Reserve administrator-equivalent managed policies to break-glass**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy"],
  "Resource": "*",
  "Condition": {
    "ArnLike": {
      "iam:PolicyARN": ["arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/IAMFullAccess"]
    },
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin" }
  }
}
```

Pair it with a Deny on `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` for
every principal outside the IAM-administration pipeline, conditioned the same way.

> `iam:PolicyARN` and `aws:PrincipalArn` require the `*Like` operators. `StringEquals`
> does not expand `*`, so a wildcarded value under it matches nothing and the guardrail
> silently permits everything it was written to deny.

**Structural controls**
- **Permissions boundaries on the principals that hold shared policies.** A boundary caps
  what any promoted version can confer, and is the only control that still works when the
  principal changing the policy is legitimately allowed to
- **Cap fan-out.** A policy attached to thirty principals is a single point of escalation
  for thirty identities; split high-fan-out policies by function and track the attachment
  count as a risk metric
- **Manage IAM through reviewed IaC**, treat out-of-band version promotion as an incident,
  and **snapshot policy versions out of the account** — the five-version cap means IAM is
  not a reliable archive of its own history
- **Enable Access Analyzer unused-access findings**, so a principal holding an escalation
  primitive it never exercises surfaces before somebody exercises it

**Detection improvements**
- Alert the ordered `CreatePolicyVersion` → `SetDefaultPolicyVersion` sequence, never
  `SetDefaultPolicyVersion` alone
- Read `isDefaultVersion` and alert the escalating document in its own right, so the
  single-call `--set-as-default` form is covered
- Anchor managed-policy ARN matching with `endswith`, never a bare term match
- Alarm on `DeletePolicyVersion` — it precedes escalation on a capped policy and it
  destroys evidence

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098.003 — Account Manipulation: Additional Cloud Roles |
| MITRE tactic | Privilege Escalation (TA0004), Persistence (TA0003) |
| Primary API | `iam:CreatePolicyVersion` → `iam:SetDefaultPolicyVersion` · `iam:AttachUserPolicy` / `AttachRolePolicy` / `AttachGroupPolicy` with `AdministratorAccess` |
| Event source | `iam.amazonaws.com` — **global service, events recorded in `us-east-1` only** |
| Key discriminator | The **decoded** document of the promoted version Allows an escalation primitive or unrestricted action, and it is default — either by `SetDefaultPolicyVersion` or by `isDefaultVersion: true` on create. Not the event name |
| Blast radius | **A count, not a name.** Every principal the policy is attached to, from `iam:ListEntitiesForPolicy` — absent from the CloudTrail event and gone once the policy is detached. Groups expand to their members |
| Field-shape traps | `CreatePolicyVersion` nests: `responseElements.policyVersion.versionId` and `.isDefaultVersion` — the flat paths are null. `CreateAccessKey` nests: `responseElements.accessKey.accessKeyId`. `Statement`, `Action` and `Resource` are each a scalar **or** an array |
| Evidence limit | Five versions per policy. `DeletePolicyVersion` before `CreatePolicyVersion` means an earlier document is unrecoverable — a precursor signal *and* a gap in the history |
| Reversal semantics | `aws iam set-default-policy-version` reverses the grant for every attached principal at once, effective on the next authorization evaluation. The verb is **not** `set-policy-default-version` |
| Blind spot | A version staged days before promotion defeats any correlation window; the `SetDefaultPolicyVersion` base rule is deployed at `low` so the promotion stays searchable |
| Error strings | `AccessDenied` on denial — not `Client.`-prefixed like EC2. Non-denial errors: `LimitExceeded` (five-version cap), `MalformedPolicyDocument`, `NoSuchEntity`, `InvalidInput` |
| Sibling technique | `../../iam.privilege-escalation.inline-policy-grant/` — same outcome via the inline route, one principal, no version history, irreversible |

**MITRE mapping note:** the source alerts tag **T1548** (*Abuse Elevation Control
Mechanism*), whose sub-techniques describe bypassing an elevation control — UAC, sudo
caching, setuid. Nothing is bypassed here: the permission is granted through the supported
API by a principal IAM authorised to call it. **T1098.003** (*Account Manipulation:
Additional Cloud Roles*) is the precise mapping and is what the shipped rules carry. A
mapping-precision note, not an operational defect — the source alerts do fire on the right
event names.

### Residual Risk

**Rollback restores the permission set; it does not un-escalate the window.** Every
principal in `blast-radius.json` held the granted permission for the whole time the version
was default, and anything any of them created in that window — access keys, login profiles,
roles, inline policies — survives the rollback and no longer references the policy. The
enumeration has to cover the whole list, not just the principal that made the change.

**Anything read during the window stays read — and you can enumerate exactly what.**
`secretsmanager:GetSecretValue`, `ssm:GetParameter*` and `kms:Decrypt` are **management**
events recorded by default, so the trail already open names precisely which secrets and
parameters each attached principal read. Do not blanket-rotate on the assumption the
telemetry is missing. CloudTrail never records the returned *value*, and
`ssm:GetParameter --with-decryption` emits a paired `kms:Decrypt`. The genuinely
data-plane read is `s3:GetObject`, which needs a data-event trail — absent one, S3 object
access in the window is unknowable.

**The version history may be incomplete before you start.** The five-version cap forces a
`DeletePolicyVersion` before a sixth, and the deleted document is unrecoverable from IAM.
If the actor cleared space, what the policy used to say is knowable only from a CloudTrail
event that may itself be outside retention.

**A staged escalation can outlive the investigation.** `CreatePolicyVersion` is inert, so
a non-default malicious version left in place is a loaded escalation awaiting one
`SetDefaultPolicyVersion` call by anyone who can make it. Query 3 finds these; deleting
them is Eradication, and skipping that step leaves the account one API call from a repeat.

**Detection coverage stays partial by construction.** The rules match substrings and event
names; the decode and `list-entities-for-policy` are what make a disposition. Until both
run continuously in the platform rather than as incident-time queries, an escalation staged
outside the correlation window reaches an analyst only if something else fires.
