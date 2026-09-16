# IR Playbook: IAM Inline Policy Grant — Self-Service Administrator through `iam:PutUserPolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Privilege escalation / Account manipulation (an inline policy is written onto a principal, handing it permissions from which it reaches account administrator) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | **High**, P0 for the self-grant and unconditioned `*:*` cases. Completion of the API call *is* the compromise — there is no exploitation stage after it and no window in which the grant exists but is not yet dangerous. For `Action:*`/`Resource:*` the blast radius is every service in the account including CloudTrail and KMS, so the escalation can destroy the evidence of itself. The source rules rate this P2, which routes an account takeover to a queue nobody reads overnight; that disposition is the single change most worth making before any rule logic is touched |
| MITRE Tactics | Privilege Escalation, Persistence |
| MITRE Techniques | T1098.003 |
| Services in Scope | IAM, STS, CloudTrail, Organizations (SCP), Access Analyzer, plus every service reachable by the granted policy |

**What the technique does:** the actor calls `iam:PutUserPolicy`, `iam:PutRolePolicy` or
`iam:PutGroupPolicy` against a principal it can already modify. Each writes an **inline**
policy document straight onto that user, role or group — one call, no approval path,
effective on the next authorization evaluation. The document need not say `*:*` to be
terminal: `iam:CreateAccessKey` against another user, `iam:CreateLoginProfile`,
`iam:AddUserToGroup`, `iam:UpdateAssumeRolePolicy`, or `iam:PassRole` paired with a
compute-create action each reach administrator in one further hop.

> The **managed-policy** route to the same outcome (`CreatePolicyVersion` →
> `SetDefaultPolicyVersion`, attaching `AdministratorAccess`) has a different blast radius
> and is reversible, so it is a separate playbook:
> `../_superseded/aws.privilege-escalation.iam-managed-policy-escalation/`.

**Why this is potent, and why the usual reflexes miss it.** The obvious audit is "which
policies does this principal have", and the obvious call is `list-attached-user-policies`
— which returns **managed policies only**. Inline policies need `list-user-policies`, a
different API, so a responder using the natural command sees a clean principal while the
inline `*:*` sits there unlisted. The second reflex, diffing against the previous
version, also returns nothing: inline policies are **not versioned**. `PutUserPolicy`
replaces the document outright and the prior content survives nowhere in IAM, so once the
CloudTrail event ages out, what that principal could do is unknowable. That single
property — no version history — is what separates this from its managed-policy sibling
and drives the evidence-first containment ordering in §3.

**Detection is the decoded document and the caller-versus-grantee comparison, not the
event name.** `PutUserPolicy` is what every legitimate IAM change looks like, so the
discriminator must come from content — an Allow statement carrying an escalation primitive
or unrestricted action — and most sharply from whether the caller granted the permission
to *itself*, which no legitimate workflow does. The source rules attempt this with a regex
for the literal `"Effect":"Allow"` — allowing zero-or-one space, on one line.
`requestParameters.policyDocument` is raw JSON in whatever whitespace the client sent, and
`--policy-document file://policy.json` submits it pretty-printed across newlines, so that
regex misses every document written the ordinary way (§2).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing IAM **management** events. IAM is **global**:
  events are recorded in **`us-east-1`** regardless of where the caller sat, so every
  `lookup-events` call below pins that region
- `PutUserPolicy` / `PutRolePolicy` / `PutGroupPolicy` carry
  `requestParameters.policyName`, `.userName` / `.roleName` / `.groupName` and
  `.policyDocument`, and return **no `responseElements`** — the grant is recorded entirely
  in the request, with no response object to pivot from
- `requestParameters.policyDocument` is **raw JSON**, in whatever whitespace the client
  sent — commonly pretty-printed across newlines from `--policy-document file://…`.
  **Do not decode it.** Percent-encoding (RFC 3986) is a property of what IAM *returns*:
  `GetUserPolicy`/`GetRolePolicy`/`GetPolicyVersion` and `responseElements` carry the
  encoded form, and the CLI and boto3 decode those for you
- IAM Access Analyzer with unused-access findings on, so a principal holding a permission
  it never exercises surfaces before an incident rather than after
- A **baseline inventory of inline policies** — `list-user-policies`,
  `list-role-policies`, `list-group-policies`, not the `list-attached-*` calls. The
  Recovery sweep compares against it and, because inline policies are unversioned, it
  cannot be reconstructed after the fact

**Alerting (must be pre-configured)**
- **Caller is also the grantee of an inline policy write (self-grant) → P0**
- **An inline document granting unconditioned `Action:*` on `Resource:*` → P0**
- **An inline document naming an escalation primitive, written by a principal outside the IAM-administration pipeline → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation and specifically not the principal that wrote the grant
- `jq`; `python3` for URL-decoding policy documents (`jq` has no urldecode builtin)
- The inline-policy baseline, and the list of role ARNs legitimately permitted to write
  IAM policy

**Known IOC Baselines**
- Which principals may call `iam:Put*Policy` at all — in most accounts one IaC deployment
  role and one break-glass role, everything else an incident
- Your own 12-digit account ID and every account ID in the organisation, so a `Principal`
  naming an outside account is recognisable on sight

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Caller is also the grantee — principal name in `userIdentity.arn` equals `requestParameters.userName`/`.roleName`/`.groupName` | CloudTrail (management) | T1098.003 |
| P0 | Decoded document grants `Action:*` on `Resource:*` in one Allow statement with no `Condition` | CloudTrail (management) | T1098.003 |
| P1 | Decoded document Allows an escalation primitive (`CreateAccessKey`, `CreateLoginProfile`, `PassRole`, `AddUserToGroup`, `UpdateAssumeRolePolicy`, any `Attach*Policy`/`Put*Policy`) | CloudTrail (management) | T1098.003 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Six or more IAM write calls denied (`AccessDenied`) for one principal in 10 minutes — boundary mapping | CloudTrail (management) | T1098.003 |
| P2 | Document textually matching `"Action": "*"` across any whitespace, without the decoded statement check | CloudTrail (management) | T1098.003 |
| P3 | Any `Put*Policy` outside the change window by an allowlisted pipeline role | CloudTrail (management) | T1098.003 |

### Detection Rule Quality Notes

The source rules search a field in one of the two formats it actually arrives in, count
denied attempts as successes, and never compare the caller to the grantee.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Regex `\x22Effect\x22:[ ]?\x22Allow\x22` allows **zero-or-one space, on one line** | `requestParameters.policyDocument` is raw JSON in the client's own whitespace, and the ordinary `--policy-document file://policy.json` submits it pretty-printed across newlines with indentation. The regex matches only documents written as one compact line, so the rule silently misses the normal case. AWS's own `PutRolePolicy` parameter pattern admits tab, LF and CR, which is the giveaway | Match tokens, not punctuation-with-assumed-spacing. IAM action names and the word `Allow` are whitespace-independent. Do structural checks — Allow vs Deny, `Action` exactly `*`, `NotAction` — by parsing |
| Nothing matches `"Action":"iam:*"` or a `NotAction` grant | `iam:*` is full IAM control, one call from administrator, and contains none of the named primitives. `{"Effect":"Allow","NotAction":"iam:DeleteUser","Resource":"*"}` grants everything but one action. Both pass every content rule silently | Add sibling blocks for `"iam:*"`/`"sts:*"` and for the token `NotAction`, ORed into the condition; handle `NotAction` in the decoded path too |
| `\x22Action\x22:[ ]?\[?\x22\*\x22\]?` matches only a scalar `"*"` or a **single-element** array | `"Action":["iam:CreateAccessKey","iam:AttachUserPolicy"]` — a textbook escalation grant — does not match, nor does `"Action":"iam:*"`. The rule catches the least subtle form and nothing else | Enumerate the escalation primitives by name as substrings; unaffected by array shape, ordering or encoding |
| `"Resource":"*"` alone is an escalation signal in the User and Group variants, and the Role variant omits that branch entirely | `{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}` is routine and fires. If the encoding defect were fixed today this becomes the dominant false positive — and three sibling rules behave one way while the fourth behaves another, so one set is wrong regardless | One rule across all three event names. Require the unrestricted **action**; treat `Resource:*` as an amplifier, never an independent trigger |
| No `errorCode` filter on any of the three rules | A principal probing `PutUserPolicy` and collecting `AccessDenied` fires the identical P2 as a completed account takeover. A sibling alert in the same set uses `NOT _exists_:errorCode`, so the idiom was known and simply not applied here | Success path filtered to `errorCode: null`; denials split into a separate volume correlation at `medium` |
| Caller and grantee are never compared | The highest-confidence discriminator available on this event is unused. Self-grant has no benign explanation and needs no tuning | Compare the principal name parsed from `userIdentity.arn` against `requestParameters.userName`/`.roleName`/`.groupName` |

**Recommended detection — an escalation primitive granted in an inline policy document.**

```yaml
# IAM Privilege Escalation via Inline Policy Grant (T1098.003)
#
# `requestParameters.policyDocument` is RAW JSON, in whatever whitespace the client sent.
# Percent-encoding is a property of what IAM RETURNS — `responseElements`, and the
# Get*Policy APIs, which state "Policies returned by this operation are URL-encoded
# compliant with RFC 3986". Do not decode request parameters.
#
# The original rules' real defect is therefore whitespace, not encoding: the regex
# `\x22Effect\x22:[ ]?\x22Allow\x22` allows zero-or-one space on a single line, and a
# document submitted with `--policy-document file://policy.json` is pretty-printed across
# newlines with indentation. It misses those entirely. They also carried no `errorCode`
# filter, so a principal probing PutUserPolicy and collecting AccessDenied fired the same
# P2 as a completed account takeover.
#
# Structural questions — Allow vs Deny, is `Action` exactly `*`, does the Allow share a
# statement with the escalation action, is there a `NotAction` — are not substring
# questions in any encoding. They need a parse. See `detection_note_t1098_003.md`.
#
# INLINE route only. The managed-policy route ships in
# ../../_superseded/aws.privilege-escalation.iam-managed-policy-escalation/
title: IAM inline policy granting a privilege-escalation primitive
id: 51344231-8c2d-4b39-9f12-a5cf033cefdb
name: iam_inline_escalation_primitive_granted
status: experimental
description: >-
  An inline IAM policy was written onto a user, role or group whose document names an
  action that is itself a privilege-escalation primitive, a service-wide IAM/STS
  wildcard, or a NotAction grant. The grantee can reach account administrator from
  these permissions alone, without any further vulnerability.
references:
  - https://attack.mitre.org/techniques/T1098/003/                      # retrieved 2026-08-27
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html  # retrieved 2026-08-27
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
      - 'PutUserPolicy'
      - 'PutRolePolicy'
      - 'PutGroupPolicy'
  # Cuts pure-Deny guardrails that merely NAME these actions. It does NOT prove the Allow
  # and the action share a statement — only a parse does that.
  allow_effect:
    requestParameters.policyDocument|contains: 'Allow'
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
  # A service wildcard over the IAM or STS namespace confers every primitive above at
  # once and contains none of their names, so it needs its own block. Quoted to avoid
  # matching a Resource ARN that merely contains the substring.
  wildcard_service:
    requestParameters.policyDocument|contains:
      - '"iam:*"'
      - '"sts:*"'
  # NotAction Allows everything EXCEPT what it lists — administrator by omission. The
  # word is bare alphanumeric and appears in no other IAM policy element.
  not_action:
    requestParameters.policyDocument|contains: 'NotAction'
  success:
    errorCode: null
  condition: selection and success and allow_effect and (escalation_action or wildcard_service or not_action)
falsepositives:
  - A guardrail that Denies these actions while Allowing something else in the same
    document — Allow and the action name are matched independently. Decode to confirm.
  - '`iam:PassRole` is deliberately NOT in the list above: it appears in a large fraction
    of legitimate IaC-managed policies and would dominate the alert volume at this level.
    It is caught by the decoded path instead — see Query 2 of the playbook.'
  - Your IAM-administration pipeline provisioning a delegated-admin role. Add its ARN to
    a `userIdentity.arn|contains` filter block once baselined.
level: high
---
# Whitespace-tolerant by regex, because the real request-side hazard is pretty-printing,
# not encoding. `--policy-document file://policy.json` submits the document across
# newlines with indentation, which any fixed-space literal match misses.
title: IAM inline policy granting unrestricted action on all resources
id: cd05c7f6-b116-46b6-83c7-d8bf812eec6c
name: iam_inline_wildcard_admin_granted
status: experimental
description: >-
  An inline IAM policy was written whose document grants Action `*` —
  administrator-equivalent access in a single statement.
references:
  - https://attack.mitre.org/techniques/T1098/003/                      # retrieved 2026-08-27
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html  # retrieved 2026-08-27
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
      - 'PutUserPolicy'
      - 'PutRolePolicy'
      - 'PutGroupPolicy'
  # \s* spans the newlines and indentation a pretty-printed document carries; the
  # optional [ handles the single-element-array form "Action": [ "*" ].
  wildcard_action:
    requestParameters.policyDocument|re: '"Action"\s*:\s*(\[\s*)?"\*"'
  success:
    errorCode: null
  condition: selection and wildcard_action and success
falsepositives:
  - A service-linked or bootstrap role legitimately provisioned with Action `*` scoped by
    a Condition block. The condition is invisible to a pattern match — decode first.
  - Multi-element arrays where `*` is not the first element, e.g. ["s3:GetObject","*"],
    are missed by this rule. The decoded path in Query 2 catches them; this rule
    under-matches rather than over-matches.
level: medium
---
title: IAM write call denied
id: 099e4832-9c7c-491d-aee7-f4bd90ae4f67
name: iam_write_denied
status: experimental
description: Base rule — volume component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html  # retrieved 2026-08-27
tags:
  - attack.discovery
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'PutUserPolicy'
      - 'PutRolePolicy'
      - 'PutGroupPolicy'
      - 'CreatePolicyVersion'
      - 'SetDefaultPolicyVersion'
      - 'AttachUserPolicy'
      - 'AttachRolePolicy'
      - 'AttachGroupPolicy'
      - 'AddUserToGroup'
      - 'CreateAccessKey'
      - 'CreateLoginProfile'
      - 'UpdateAssumeRolePolicy'
  denied:
    errorCode|contains: 'AccessDenied'
  condition: selection and denied
level: low
---
# Kept strictly separate from the success-path rules. A principal collecting AccessDenied
# across IAM write calls is mapping its own permission boundary to find an escalation
# path it CAN reach — reconnaissance, not compromise, and it must not share an alert with
# a completed takeover. The original rules had no errorCode filter at all, so denied
# probing and successful escalation fired the identical P2.
#
# This correlation deliberately spans BOTH the inline and managed routes: an actor
# probing does not know in advance which will work, so scoping it to one route would
# split the very signal that makes it meaningful.
#
# Threshold basis: derived from operator behaviour, not an observed baseline. A human who
# hits an IAM permissions error retries once or twice then stops or asks a colleague;
# automation with a stale policy retries on a fixed interval, which the per-principal
# grouping and short window separate out. Six or more denials in ten minutes sits above
# ordinary human retry. Baseline against your own account before deploying — a starting
# point, not a measurement.
title: IAM write calls denied repeatedly for one principal
id: f42eb8f9-0e32-4bbe-8ce0-846241d27043
status: experimental
description: >-
  One principal was denied six or more IAM write calls within ten minutes — the signature
  of an actor enumerating which escalation primitives its credentials can reach.
references:
  - https://attack.mitre.org/techniques/T1098/003/                      # retrieved 2026-08-27
tags:
  - attack.discovery
  - attack.t1098.003
correlation:
  type: event_count
  rules:
    - iam_write_denied
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gt: 5
level: medium
```

Reproduced byte-for-byte from the first rule document of
`detections/sigma_t1098_003.yml` (the file's leading comment block, which records what
the original rules got wrong, is not repeated — §2 above says the same thing in prose).
Three further documents ship in that file: the encoding-fragile wildcard rule (`medium`),
and the denied-IAM-write base rule (`low`) with its volume correlation (`medium`).
**Deploy the file, not this excerpt.**

**What these rules structurally cannot do.** They match substrings, and three questions
decide whether a document is an escalation: Allow or Deny, is `Action` exactly `*` or
merely something containing an asterisk, and do the Allow and the action share a
statement. None is a substring question. Answering them needs decode → parse → iterate —
Query 2 below and the `parse_json()` path in `detections/kql_t1098_003.kql`. **Treat a
Sigma hit as the trigger for the decode, not as a disposition.** Full reasoning is in
`detections/detection_note_t1098_003.md`.

---

### Key Investigation Queries

> **IAM is a global service — its CloudTrail events land in `us-east-1` only.** Running these against the caller's own region returns zero. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who granted what, to whom, and was it a self-grant

```bash
REGION="us-east-1"; WINDOW="24 hours ago"

for EV in PutUserPolicy PutRolePolicy PutGroupPolicy; do
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
    ((if ($arn | test(":assumed-role/")) then $p[1] else $p[-1] end)) as $caller |
    ((.requestParameters.userName // .requestParameters.roleName
      // .requestParameters.groupName // "")) as $grantee |
    {time: .eventTime, event: .eventName,
     caller_arn: $arn, caller_name: $caller,
     access_key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 4
     grantee: $grantee,
     principal_kind: (.eventName | sub("^Put";"") | sub("Policy$";"") | ascii_downcase),
     self_grant: ($grantee != "" and $caller == $grantee),
     policy_name: .requestParameters.policyName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

**`self_grant: true` with `error: "SUCCESS"` ends the investigation phase** — go to
Containment. Rows with an `error` are the probing path: count them per `caller_arn`,
never score them as grants — a principal collecting `AccessDenied` across IAM writes is
mapping which primitives it can reach, which makes it compromised without anything having
succeeded. `principal_kind` is `user`, `role` or `group` and tells Containment Step 1
which `delete-*-policy` call to make. Record `caller_arn`, `access_key`, `grantee`,
`principal_kind`, `policy_name` and the grant `time`.

#### Query 2 — Inspect: decode the granted documents and read them statement by statement

CloudTrail holds the policy in whichever encoding the client sent. `decode_policy_documents.py`
decodes unconditionally, then evaluates each statement in isolation — answering the three
questions no substring match can. It ships in the kit's `tools/`, is shared with the
managed-policy playbook, and carries the scalar-or-array shape guards that an ad-hoc `jq`
sweep gets wrong.

```bash
REGION="us-east-1"; WINDOW="24 hours ago"
KIT="<path-to-playbook-authoring-kit>"

for EV in PutUserPolicy PutRolePolicy PutGroupPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -c '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) |
    {time: .eventTime, caller: .userIdentity.arn,
     grantee: (.requestParameters.userName // .requestParameters.roleName
               // .requestParameters.groupName),
     policy_name: .requestParameters.policyName,
     doc: .requestParameters.policyDocument}' | \
  python3 "$KIT/tools/decode_policy_documents.py"
```

`[!] FULL ADMIN` is terminal — the grantee owned the account from that timestamp.
`[!] PRIMITIVE` names the actions granted, and that list *is* the eradication work-list.
`[i] WILDCARD` with `condition=True` is usually a service-scoped grant confined by a
condition key: disposition it, do not act. A document that will not parse after decoding
is double-encoded or malformed — read it by hand, do not assume it is benign.

#### Query 3 — Sweep: every principal in the account holding an inline escalation grant

`list-attached-*-policies` returns managed policies only, so an inline `*:*` is invisible
to it. This walks the inline enumeration for all three principal types.

```bash
# jq, not grep: `--output json` pretty-prints, so a line-oriented regex misses
# "Action": [\n  "*"\n]. Statement and Action are each a scalar OR an array, and
# iterating a bare object yields its KEYS — the statement is then silently skipped.
UNRESTRICTED='[ (.Statement // [] | if type=="object" then [.] else . end)[]
                | select(.Effect == "Allow")
                | ((.Action // []) | if type=="string" then [.] else . end)[] ]
              | any(. == "*")'

for KIND in user role group; do
  case "$KIND" in
    user)  NAMES=$(aws iam list-users  --query 'Users[].UserName'  --output text) ;;
    role)  NAMES=$(aws iam list-roles  --query 'Roles[].RoleName'  --output text) ;;
    group) NAMES=$(aws iam list-groups --query 'Groups[].GroupName' --output text) ;;
  esac
  for N in $NAMES; do
    for P in $(aws iam list-${KIND}-policies --${KIND}-name "$N" \
                 --query 'PolicyNames[]' --output text 2>/dev/null); do
      aws iam get-${KIND}-policy --${KIND}-name "$N" --policy-name "$P" \
        --query 'PolicyDocument' --output json \
        | jq -e "$UNRESTRICTED" >/dev/null 2>&1 \
        && echo "[!] ${KIND}/$N inline '$P' grants unrestricted Action"
    done
  done
done
echo "[OK] Inline escalation sweep complete"
```

> `get-user-policy` / `get-role-policy` / `get-group-policy` return the document **already
> decoded** by the CLI — a JSON object. This is the response side, where percent-encoding
> genuinely applies: the API returns it RFC 3986-encoded and botocore's `after-call.iam`
> handler decodes it before you see it. The CloudTrail *request* parameter is raw JSON and
> needs no decode. Do not reuse this `jq` on event data: it assumes a parsed object.

Every `[!]` is a principal that can reach administrator right now, incident-related or
not. Reconcile against the §1 baseline: here and not there is this incident; in both is
pre-existing exposure for the §6 findings. Run the managed-policy playbook's sweep as
well — this one is blind to `AdministratorAccess` attachments by design.

#### Query 4 — Session reconstruction: what the principal did after the grant

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
GRANT_TIME="<time-from-Query-1>"          # ISO8601, the moment the grant succeeded

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg t "$GRANT_TIME" '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     phase: (if .eventTime > $t then "AFTER-GRANT" else "before" end),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

The **"was it used"** pivot. Every `AFTER-GRANT` row succeeding on a call that would have
been denied before is the escalation being exercised; the ones that matter —
`CreateAccessKey`, `CreateLoginProfile`, `CreateUser`, `CreateRole`,
`UpdateAssumeRolePolicy`, `AssumeRole` into a new role — outlive the policy you are about
to delete. IAM management events are complete, so an empty `AFTER-GRANT` set is real
evidence *this credential* did not exercise the grant. It is **not** evidence the grant
went unused: a key minted in the window has its own `accessKeyId` and appears only in its
own session. Re-run per key from Containment Step 2 until it converges.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Removing an inline policy is immediately effective — authorization is evaluated per request
against current policy, so the grantee loses the permission on its next call with no session
revocation required. That inverts the usual ordering: because inline policies are
**unversioned**, the priority is to **capture the document before deleting it**, then to
catch the credentials the grantee minted while it held the permission — those outlive it.

> Run every command under the **break-glass responder credentials** from §1 — not under
> any principal being contained, and not under the principal that wrote the grant.

#### Step 1 — Capture the policy document, then remove the grant

```bash
GRANTEE="<grantee-from-Query-1>"
KIND="<principal-kind-from-Query-1>"         # user | role | group
POLICY_NAME="<policy-name-from-Query-1>"
EVIDENCE="/tmp/ir-iam-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$EVIDENCE"

# Inline policies are NOT versioned — deleting one destroys the only live copy.
if aws iam get-${KIND}-policy --${KIND}-name "$GRANTEE" --policy-name "$POLICY_NAME" \
     --output json > "$EVIDENCE/inline-${KIND}-${POLICY_NAME}.json" 2>/dev/null; then
  echo "[OK] Captured to $EVIDENCE/inline-${KIND}-${POLICY_NAME}.json"
  aws iam delete-${KIND}-policy --${KIND}-name "$GRANTEE" --policy-name "$POLICY_NAME" && \
    echo "[OK] Removed inline policy '$POLICY_NAME' from ${KIND} $GRANTEE — effective immediately"
else
  rm -f "$EVIDENCE/inline-${KIND}-${POLICY_NAME}.json"
  echo "[!] '$POLICY_NAME' not found as an inline policy on ${KIND} $GRANTEE — already removed, or KIND is wrong. Re-read Query 1's principal_kind field"
fi
```

#### Step 2 — Neutralise credentials the grantee minted during the window

These survive the policy removal, and they are the actual persistence.

```bash
REGION="us-east-1"
GRANT_TIME="<time-from-Query-1>"
GRANTEE="<grantee-from-Query-1>"

# responseElements NESTS: responseElements.accessKey.accessKeyId (flat path is null).
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time "$GRANT_TIME" --region "$REGION" --output json | \
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

aws iam get-login-profile --user-name "$GRANTEE" >/dev/null 2>&1 && \
  echo "[!] $GRANTEE has a console login profile — confirm it predates $GRANT_TIME"
```

> Disable, do not delete. An inactive key stays enumerable and keeps its creation
> metadata; deleting it removes the evidence of what the attacker built.

#### Step 3 — Revoke the grantee's existing sessions

Policy removal handles permissions. This handles a role whose credentials were already
exported off the instance.

```bash
GRANTEE="<grantee-from-Query-1>"

if aws iam get-role --role-name "$GRANTEE" >/dev/null 2>&1; then
  aws iam put-role-policy --role-name "$GRANTEE" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}}]}' && \
    echo "[OK] Revoked pre-existing sessions for role $GRANTEE"
else
  echo "[i] $GRANTEE is not a role — key disablement in Step 2 is the control here"
fi
```

> `aws:TokenIssueTime` denies only tokens issued **before** the cutoff — a credential
> re-fetched from IMDS afterwards is not denied. It kills currently-leaked session tokens;
> it does not gate the role or stop fresh theft from a still-compromised host.

#### Step 4 — Contain the granting principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REVOKE_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}'
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["iam:PutUserPolicy","iam:PutRolePolicy","iam:PutGroupPolicy","iam:AttachUserPolicy","iam:AttachRolePolicy","iam:AttachGroupPolicy","iam:CreatePolicyVersion","iam:SetDefaultPolicyVersion","iam:CreateAccessKey","iam:CreateLoginProfile","iam:UpdateAssumeRolePolicy","iam:AddUserToGroup"],"Resource":"*"}]}'

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

> If the grant arrived through CloudFormation, `userIdentity.arn` is still the submitting
> principal and `invokedBy` is `cloudformation.amazonaws.com`. Contain the principal *and*
> disable the stack's update path, or the next drift reconciliation re-applies the policy.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm every grant in the window has been reversed

Work Query 1's full list, not the event that raised the alert — an actor who found one
writable principal usually tried several, and the successes do not all raise the same
alert. For each row with `error: "SUCCESS"`, confirm the inline policy is gone from the
principal named, using the `list-<kind>-policies` call matching its `principal_kind`.

#### Remove the persistence the escalation established

From Query 4's `AFTER-GRANT` rows and Step 2's key sweep, in order of how long each
outlives the policy:

- **Access keys** created after `GRANT_TIME` — disabled in Step 2, delete once documented
- **Login profiles** — `aws iam delete-login-profile --user-name <user>` for any created
  in the window
- **New users and roles** — a role created in the window whose trust policy names an
  outside account is a full re-entry path, and is the role-trust-backdoor playbook
- **Group membership** — `AddUserToGroup` into an admin group grants what an inline
  policy would and appears in no `list-*-policies` call
- **Managed-policy changes** — if Query 4 shows `CreatePolicyVersion` or `Attach*Policy`,
  work `../_superseded/aws.privilege-escalation.iam-managed-policy-escalation/` before closing

#### Right-size the permission that made this possible

```bash
echo "[i] Identify which policy on the grantor permits iam:Put*Policy:"
aws iam list-attached-role-policies --role-name "<grantor-role-name>" --output table 2>/dev/null
aws iam list-role-policies          --role-name "<grantor-role-name>" --output table 2>/dev/null
aws iam list-attached-user-policies --user-name "<grantor-user-name>" --output table 2>/dev/null
aws iam list-user-policies          --user-name "<grantor-user-name>" --output table 2>/dev/null
```

The durable fix is not removing `iam:PutUserPolicy` from the grantor — many principals
legitimately need it. It is a **permissions boundary** on every principal the grantor can
write to, capping what any written document can confer. See §6.

#### Remove emergency policies once clean

```bash
for RN in "<grantor-role-name>" "<grantee-role-name>"; do
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyRevokeSessions" 2>/dev/null
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyDenyIAMWrite"   2>/dev/null
done
# Step 4 uses put-user-policy when the grantor was an IAM USER — that path needs the
# user-side removal, which delete-role-policy does not cover.
aws iam delete-user-policy --user-name "<grantor-user-name>" --policy-name "EmergencyDenyIAMWrite" 2>/dev/null
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

#### Verify the granted policy is gone

```bash
GRANTEE="<grantee-from-Query-1>"
KIND="<principal-kind-from-Query-1>"
POLICY_NAME="<policy-name-from-Query-1>"

FOUND=$(aws iam list-${KIND}-policies --${KIND}-name "$GRANTEE" \
          --query 'PolicyNames[]' --output text 2>/dev/null \
        | tr '\t' '\n' | grep -Fx "$POLICY_NAME" | wc -l | tr -d ' ')
[ "$FOUND" -eq 0 ] && echo "[OK] Inline policy '$POLICY_NAME' is absent from ${KIND} $GRANTEE" \
                   || echo "[FAIL] '$POLICY_NAME' is still attached to ${KIND} $GRANTEE"
```

#### Verify no access key created during the window is still active

```bash
REGION="us-east-1"; GRANT_TIME="<time-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time "$GRANT_TIME" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) |
         "\(.responseElements.accessKey.userName) \(.responseElements.accessKey.accessKeyId)"' \
  > /tmp/ir-window-keys-verify.txt        # response side: always present, unlike requestParameters.userName

STILL_ACTIVE=0
while read -r U K; do
  [ -z "$U" ] && continue
  S=$(aws iam list-access-keys --user-name "$U" \
        --query "AccessKeyMetadata[?AccessKeyId=='$K'].Status" --output text 2>/dev/null)
  [ "$S" = "Active" ] && { echo "[FAIL] key $K on $U created after $GRANT_TIME is still Active"; STILL_ACTIVE=$((STILL_ACTIVE+1)); }
done < /tmp/ir-window-keys-verify.txt

[ "$STILL_ACTIVE" -eq 0 ] && echo "[OK] No key created after $GRANT_TIME remains Active" \
                          || echo "[FAIL] $STILL_ACTIVE window-created key(s) still Active"
```

#### Re-run the account-wide sweep

```bash
echo "[i] Re-run Query 3. Every [!] must now appear in the §1 inline-policy baseline; any [!] absent from it is unremediated."
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rules MUST fire on:"
echo "  eventSource=iam.amazonaws.com  eventName=PutUserPolicy  errorCode absent"
echo "  requestParameters.userName = the principal named in userIdentity.arn (self-grant)"
echo "  requestParameters.policyDocument, fed COMPACT and PRETTY-PRINTED:"
echo '    compact {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]}'
echo '    pretty  {\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "iam:CreateAccessKey"\n    }\n  ]\n}'
echo "  -> iam_inline_escalation_primitive_granted, level high, on BOTH. A rule that fires"
echo "     on the compact form only is the original defect, reintroduced."
echo "  Also feed, each of which MUST fire high:"
echo '    {"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}          -> wildcard_service'
echo '    {"Statement":[{"Effect":"Allow","NotAction":"iam:DeleteUser","Resource":"*"}]} -> not_action'
echo '    an event with requestParameters {"omitted": true}                            -> the omitted-params rule'"'"
echo
echo "The rules MUST NOT fire on:"
echo "  1. The same event with errorCode=AccessDenied — that is the denied-burst"
echo "     correlation at medium, never the high-confidence rule"
echo '  2. A Deny-only guardrail naming the same action, or a narrow grant such as'
echo '     {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"} — no primitive named,'
echo "     and Resource:* alone is not a trigger"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could write an inline policy onto another principal, or onto itself | `iam:Put*Policy` held outside the IAM-administration pipeline, with no permissions boundary capping what a written policy can confer |
| The grant was not detected | The deployed rules searched the policy document in one of the two formats CloudTrail actually stores, and had no `errorCode` filter, so successes and failed probes were indistinguishable |
| Self-grant went unnoticed | Caller and grantee were never compared, discarding the one discriminator on this event that needs no tuning |
| The prior permission set could not be reconstructed | Inline policies are unversioned and no baseline existed, so "what was this principal allowed to do" had no answer outside CloudTrail retention |
| Credentials minted during the window outlived remediation | Removing the policy was treated as the end of the incident; keys and login profiles created while it was held are unaffected by its deletion |

### Recommended Guardrails

**Require a permissions boundary on every principal a non-admin can create or modify**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["iam:CreateUser", "iam:CreateRole"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "iam:PermissionsBoundary": "arn:aws:iam::*:policy/DeveloperBoundary" },
    "ArnNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iam-admin", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

Pair it with a second Deny on `iam:DeleteUserPermissionsBoundary`,
`iam:DeleteRolePermissionsBoundary`, `iam:PutUserPermissionsBoundary` and
`iam:PutRolePermissionsBoundary`, conditioned the same way — a boundary a principal can
remove is not a boundary.

> **Every wildcarded condition value needs a `*Like` operator** — `iam:PermissionsBoundary`
> above, and `aws:PrincipalArn` / `iam:PolicyARN` in any attach-scoping guardrail. The
> equality operators do not expand `*`. Get the failure direction right, because it
> differs by shape: `Deny` + `StringNotEquals` against a wildcard matches *everything* and
> denies the very requests the boundary was meant to permit — an outage. `Deny` +
> `StringEquals` against a wildcard matches *nothing* and permits everything it was
> written to deny — a silent bypass.

**Structural controls**
- **Permissions boundaries are the only control that survives a legitimate grantor.**
  Every allowlist here necessarily exempts the IAM-administration pipeline; a boundary
  caps the conferred permission regardless of who wrote it
- **Manage IAM through reviewed IaC** and treat any out-of-band `Put*Policy` as an
  incident — the allowlist then has one entry and everything else is signal
- **Snapshot inline policies on a schedule** — the only way to answer "what changed" for
  an object IAM does not version — and enable Access Analyzer unused-access findings, so
  a principal holding a primitive it never exercises surfaces before somebody uses it

**Detection improvements**
- Deploy the whitespace-independent rules; never a fixed-spacing regex
- Split denied from successful on every IAM write rule — different incidents, different
  levels; and add the caller-versus-grantee comparison in the platform query, which is
  the highest-confidence signal here and the one Sigma cannot express

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098.003 — Account Manipulation: Additional Cloud Roles |
| MITRE tactic | Privilege Escalation (TA0004), Persistence (TA0003) |
| Primary API | `iam:PutUserPolicy` / `iam:PutRolePolicy` / `iam:PutGroupPolicy` |
| Event source | `iam.amazonaws.com` — **global service, events recorded in `us-east-1` only** |
| Key discriminator | The **decoded** document Allows an escalation primitive or unrestricted action, and — the unambiguous case — the caller's own principal name equals the grantee. Not the event name |
| Ground truth / pivot | `requestParameters.policyDocument` decoded and iterated per statement. "Was it used": session reconstruction by `accessKeyId` after the grant time — IAM management events are complete, so absence is meaningful for that credential only |
| Field-shape traps | `Put*Policy` return **no `responseElements`**. `CreateAccessKey` nests: `responseElements.accessKey.accessKeyId`. `Statement`, `Action` and `Resource` are each a scalar **or** an array |
| Blast radius | Whatever the document grants, on **one** principal. For unconditioned `*:*`: the entire account, including CloudTrail and KMS, so the escalation can erase its own evidence |
| Error strings | `AccessDenied` on denial — not `Client.`-prefixed like EC2. Non-denial errors on the same calls: `MalformedPolicyDocument`, `NoSuchEntity`, `InvalidInput`, and `LimitExceeded` for the size cap — inline aggregate is 2,048 chars per user, 10,240 per role, 5,120 per group; managed policies 6,144 each. **There is no size-based evasion path here:** those caps sit 12–50× below CloudTrail's 100 KB `requestParameters` omission threshold, so an oversized document is rejected outright rather than logged with its body missing |
| Reversal semantics | Policy removal is effective on the next authorization evaluation — no session revocation needed for the permission itself. The prior document is **unrecoverable**; credentials minted while it was held are unaffected |
| Sibling technique | `../_superseded/aws.privilege-escalation.iam-managed-policy-escalation/` — same outcome via the managed-policy route, different blast radius and reversible |

**MITRE mapping note:** the source alerts tag **T1548** (*Abuse Elevation Control
Mechanism*), whose sub-techniques describe bypassing an elevation control — UAC, sudo
caching, setuid. Nothing is bypassed here: the permission is granted through the supported
API, by a principal IAM authorised to call it, and the control behaves exactly as
configured. **T1098.003** (*Account Manipulation: Additional Cloud Roles*) is the precise
mapping and is what the shipped rules carry. A mapping-precision note, not an operational
defect — the source alerts do fire on the right event names, and the tactic is right
either way.

### Residual Risk

**The policy is gone; what it was used to build is not.** Every access key, login
profile, user, role and group membership created during the window persists after the
grant is deleted, and each is an independent re-entry path that no longer references the
policy. Step 2 and Query 4 find the ones recorded under the credential you know about — a
key minted inside the window has its own `accessKeyId` and appears only in its own session
history, so the enumeration repeats per key until it converges. A role whose trust policy
was rewritten in the window is a further re-entry path that survives everything here, and
is its own playbook.

**The prior document is gone too.** Inline policies are unversioned, so once the grant is
deleted the only record of what the principal was allowed to do — before *and* after — is
the CloudTrail event. If that event ages out of retention, the question becomes
permanently unanswerable. Preserve `$EVIDENCE` outside the account.

**Anything the escalated principal read stays read — but you can enumerate exactly what.**
`secretsmanager:GetSecretValue`, `ssm:GetParameter`/`GetParameters`/`GetParametersByPath`
and `kms:Decrypt` are **management** events recorded by default, so the trail you already
have open names precisely which secrets and parameters were read in the window. Do not
blanket-rotate on the assumption the telemetry is missing. CloudTrail never records the
returned *value*, and `ssm:GetParameter --with-decryption` emits a paired `kms:Decrypt`.
The genuinely data-plane read is `s3:GetObject`, which needs a data-event trail — absent
one, S3 object access in the window is unknowable and those objects must be treated as
disclosed.

**Detection coverage stays partial by construction.** The rules match substrings; the
decode makes the disposition. Until that decoded check runs continuously in the platform
rather than as an incident-time query, a policy whose escalation is structural — an Allow
and an action that only matter in combination — passes the rules and reaches an analyst
only if something else fires.
