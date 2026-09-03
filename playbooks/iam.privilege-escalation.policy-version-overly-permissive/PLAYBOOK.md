# IR Playbook: IAM Policy Authored With Administrative Permissions — `Action: "*"` via `CreatePolicyVersion`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Privilege escalation — a managed policy is authored granting `Action: "*"`, either taking effect immediately or lying dormant as a pre-loaded escalation |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when the administrative version is operative; high for a newly created administrative policy; medium when the version is dormant. The source rule rates every case P2 and cannot tell them apart. |
| MITRE Tactics | Persistence; Privilege Escalation |
| MITRE Techniques | T1098.003 |
| Services in Scope | IAM, CloudTrail, AWS Organizations |

**What the technique does:** the actor writes a policy document granting `Action: "*"`. Whether that
is an escalation depends on one flag the source rule never reads. AWS on `SetAsDefault`: *"When this
parameter is `true`, the new policy version becomes the operative version. That is, it becomes the
version that is in effect for the IAM users, groups, and roles that the policy is attached to."*
Without it, the version is **dormant** — it grants nobody anything, and it sits inside the policy as
a pre-loaded escalation that one later call activates with no document write for anyone to review.

**Why the usual reflexes miss it.** The first is to match the document as a string: a substring
cannot tell whether the `Allow` and the wildcard are in the **same statement**, so a narrow `Allow`
beside a `Deny` on `Action:"*"` — the safest shape available — matches. The second is to treat
`Resource: "*"` as equivalent to `Action: "*"`: many legitimate actions accept no other `Resource`
value, so this is the largest false-positive source in the pack and its real cost is teaching
responders that the whole rule family is noise. The third is to ignore `setAsDefault` and rate a
draft like a live grant. The fourth is to watch only `CreatePolicyVersion`, when a brand-new
administrative policy is the same escalation under `CreatePolicy`.

**Detection thesis:** rate on `Action: "*"` and never on `Resource: "*"`, split live from dormant by
reading `setAsDefault`, and resolve the same-statement question by parsing rather than matching.

**Adjacent playbooks.** Activating a version — including one authored long before — is
`../iam.privilege-escalation.default-policy-version-reverted/`. Attaching an existing policy to a
principal is `../iam.privilege-escalation.admin-policy-attached/`. Inline policies are
`../iam.privilege-escalation.inline-policy-grant/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

**A multi-Region CloudTrail with `IncludeGlobalServiceEvents`.** IAM is a global service: its events
are recorded in `us-east-1` and CloudTrail delivers global service events *only* to single-Region
trails there. Without one, every rule here is silently inert.

`tools/decode_policy_documents.py` available to the responder. Triage for this use case is a parse,
not a judgement, and doing it by eye is how a `Deny`-only policy gets escalated and a
same-statement grant gets closed.

A recorded list of the policies that are administrative **on purpose** — break-glass, the
provisioning role's own policy, any deliberately unrestricted automation policy. Without it, every
alert needs a conversation before it can be rated.

**Alerting (must be pre-configured)**

- **`CreatePolicyVersion` with `setAsDefault: true` and a document granting `Action: "*"` → P0**
- **`CreatePolicy` with a document granting `Action: "*"` by a principal not on the provisioner list → P0**

**Response Tooling**

An IAM principal that can call `iam delete-policy-version`, `get-policy-version`,
`list-policy-versions`, `list-entities-for-policy` and `set-default-policy-version` outside the
change pipeline.

**Known IOC Baselines**

The roles that own IAM policy lifecycle, populating `known_provisioners`. Every infrastructure apply
that updates a managed policy is `CreatePolicyVersion` with `setAsDefault: true`, so without this
list the critical rule fires on every deployment and will be switched off within a week.

The current inventory of **non-default** policy versions granting `Action: "*"`. These are pre-loaded
escalations that already exist, and they will not appear in any write-time alert because nothing is
being written.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `CreatePolicyVersion` with `setAsDefault: true` and a document granting `Action: "*"` | CloudTrail | T1098.003 |
| P0 | `CreatePolicy` with a document granting `Action: "*"`, by a principal not on the provisioner list | CloudTrail | T1098.003 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `CreatePolicyVersion` granting `Action: "*"` with `setAsDefault` absent or false — dormant, and one call from live | CloudTrail | T1098.003 |
| P2 | An administrative policy authored and then attached to a principal by the same principal | CloudTrail | T1098.003 |
| P2 | A document containing `Action: "*"` and no `Allow` at all — almost certainly a `Deny` policy, and the shape the source rule cannot distinguish | CloudTrail | T1098.003 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| A substring match cannot scope to a statement | `"Effect":"Allow"` and `"Action":"*"` both appear in a document with a narrow `Allow` and a separate `Deny *` — the safest shape there is. The rule fires on it | Neither Sigma nor KQL can scope to a JSON statement, so the rules over-match **by design** and §2 Query 2 parses the document. The query also surfaces the no-`Allow` case as a cheap approximation |
| `Resource: "*"` OR-ed with `Action: "*"` at one severity | `s3:ListAllMyBuckets`, `ec2:DescribeInstances` and `iam:ListRoles` accept no other `Resource` value, so correct least-privilege policies match. The cost is not volume — it is teaching responders the rule family is noise | `Action: "*"` only in the alerting rules; the `Resource`-only shape ships at informational, explicitly to record that it is expected |
| `setAsDefault` never read | A dormant version grants nobody anything. Rating a draft awaiting approval identically to a live administrative grant is wrong in both directions | Split into a critical live rule and a medium dormant rule, which have different remediations — contain versus delete |
| `CreatePolicy` not covered anywhere in the pack | A brand-new administrative policy is the same escalation under a different event name, and it is the earliest signal available because the policy is attached to nothing yet | A dedicated rule at high |
| No principal filter | Every infrastructure apply that updates a managed policy is this exact call | `known_provisioners`, shipped with placeholders that must be populated |
| Rated P2, MITRE: none | One rating for four materially different situations | Critical / high / medium / informational by effect; `T1098.003` |

**Recommended detection — administrative content, split by whether it is actually in effect.**

```yaml
# IAM managed policy authored with administrative permissions (T1098.003)
#
# A SUBSTRING MATCH CANNOT READ A POLICY, AND THE SOURCE RULE IS A SUBSTRING MATCH.
# It requires `"Effect":"Allow"` AND (`"Action":"*"` OR `"Resource":"*"`) to appear anywhere in the
# serialised document. It cannot answer the one question that decides whether the policy is
# dangerous: do the Allow and the wildcard sit in the SAME statement? A document with a narrow Allow
# and a separate `Deny` on `Action:"*"` — the safest shape there is — satisfies every clause.
# Credit where it is due: the regex anchors on exactly `"*"`, so it does NOT confuse `"s3:Get*"`
# with `"*"`. That part is right. The statement-scoping is the part that is not, and Sigma cannot
# express it either — which is why §2 of ../PLAYBOOK.md parses the document rather than matching it.
#
# `Resource: "*"` IS NORMAL AND OR-ING IT WITH `Action: "*"` IS THE LARGEST FALSE-POSITIVE SOURCE.
# Many legitimate actions accept no other value — s3:ListAllMyBuckets, ec2:DescribeInstances,
# iam:ListRoles. A policy granting exactly those is correct and matches the source rule. `Action:"*"`
# is administrative; `Resource:"*"` is a shape. They ship at different severities below.
#
# A VERSION THAT IS NOT DEFAULT GRANTS NOTHING. AWS: SetAsDefault "becomes the version that is in
# effect for the IAM users, groups, and roles that the policy is attached to." Without it the new
# version is dormant. The source rule does not read the flag, so it rates an unactivated draft
# identically to a live escalation — and it also misses that a dormant permissive version is a
# PRE-LOADED escalation, one SetDefaultPolicyVersion call away, which is a different and
# longer-lived finding. Both ship, at different levels.
#
# AND IT ONLY WATCHES `CreatePolicyVersion`. A brand-new policy created administrative is the same
# escalation under `CreatePolicy`, which the pack does not cover anywhere.
#
# Related: ../../iam.privilege-escalation.default-policy-version-reverted/ covers ACTIVATION,
# including of versions authored long before. This directory covers CONTENT. They overlap on
# create-and-activate by design — one reads the flag, the other reads the document.
title: IAM managed policy version authored with Action "*" and made operative
id: 7d51e9a3-2c80-4b47-91f6-a3e02c8b415d
name: iam_policy_version_admin_and_default
status: experimental
description: >-
  CreatePolicyVersion succeeded with setAsDefault true and a document granting Action "*". This is
  live administrative access applied to every principal the policy is attached to, in one call. The
  match is deliberately narrow — Action "*" only, not Resource "*" — because the two are not
  equivalent and rating them alike is what makes this class of rule unusable.
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
  # Four keys ANDed, and they do co-occur on a single event: a CreatePolicyVersion record carries
  # eventSource, eventName, the setAsDefault flag and the submitted document together.
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreatePolicyVersion'
    requestParameters.setAsDefault: true
    requestParameters.policyDocument|contains:
      - '"Action":"*"'
      - '"Action": "*"'
      - '"Action":["*"]'
      - '"Action": ["*"]'
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
    A deliberately administrative policy being updated — a break-glass policy, or an
    infrastructure role's own policy. It should be a short, known list; if the provisioner
    allowlist does not cover it, the policy inventory is the thing to fix.
  - >-
    A document whose only Action "*" sits inside a Deny. Sigma cannot scope a match to a statement,
    so this is a known and accepted false positive, resolved by the parser in §2 Query 2.
level: critical
---
title: IAM managed policy version authored with Action "*" but left dormant
id: 1b48f60c-97d2-4e53-8a01-5cf7d2e94b68
name: iam_policy_version_admin_dormant
status: experimental
description: >-
  CreatePolicyVersion succeeded with a document granting Action "*" and setAsDefault absent or
  false. Nothing is granted yet — the version is not operative — so this is not an escalation. It is
  a pre-loaded one: the permissive text now exists inside a policy that may be attached to many
  principals, and a single SetDefaultPolicyVersion call activates it with no document write for
  anyone to review. Shipped at medium because the window to remove it is open and long.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
  - https://attack.mitre.org/techniques/T1098/003/
tags:
  - attack.persistence
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  # Keys ANDed, and they do co-occur on a single event: the record carries eventSource,
  # eventName and the submitted document together. `activated` is a sibling, negated below.
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreatePolicyVersion'
    requestParameters.policyDocument|contains:
      - '"Action":"*"'
      - '"Action": "*"'
      - '"Action":["*"]'
      - '"Action": ["*"]'
  success:
    errorCode: null
  activated:
    requestParameters.setAsDefault: true
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not activated and not known_provisioners
falsepositives:
  - >-
    A staged policy change awaiting approval, which is exactly this shape and is good practice.
    The distinguishing question is whether an approval record exists, not whether the event looks
    unusual.
level: medium
---
title: IAM policy created with administrative permissions
id: c04a7b25-63f1-49de-b8a7-30e5169cf742
name: iam_policy_created_admin
status: experimental
description: >-
  CreatePolicy succeeded with a document granting Action "*". A brand-new administrative policy is
  the same escalation as an administrative policy version, under an event name the source pack does
  not watch anywhere. A newly created policy is attached to nothing, so it grants nobody anything
  until an Attach call follows — which makes this the earliest point at which the intent is visible.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicy.html
  - https://attack.mitre.org/techniques/T1098/003/
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  # Keys ANDed, and they do co-occur on a single event: the record carries eventSource,
  # eventName and the submitted document together.
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreatePolicy'
    requestParameters.policyDocument|contains:
      - '"Action":"*"'
      - '"Action": "*"'
      - '"Action":["*"]'
      - '"Action": ["*"]'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A deliberately administrative policy being created as part of a new environment. It should
    arrive from the provisioning role; from anywhere else it is worth a question.
level: high
---
title: IAM policy authored with Resource "*" and no Action wildcard
id: 9e3706fd-8a14-42cb-b05f-c7261de4830a
name: iam_policy_resource_wildcard_only
status: experimental
description: >-
  Base rule — informational, and shipped explicitly to record that this shape is NORMAL rather than
  to alert on it. A policy granting Resource "*" without Action "*" is what many legitimate actions
  require: s3:ListAllMyBuckets, ec2:DescribeInstances and iam:ListRoles accept no other value. The
  source rule ORs this with Action "*" at the same severity, which is the largest false-positive
  source in that pack. Routed to a log for inventory, never to a human.
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
tags:
  - attack.persistence
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  # Keys ANDed, and they do co-occur on a single event: the record carries eventSource,
  # eventName and the submitted document together.
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'CreatePolicy'
      - 'CreatePolicyVersion'
    requestParameters.policyDocument|contains:
      - '"Resource":"*"'
      - '"Resource": "*"'
  success:
    errorCode: null
  action_wildcard:
    requestParameters.policyDocument|contains:
      - '"Action":"*"'
      - '"Action": "*"'
      - '"Action":["*"]'
      - '"Action": ["*"]'
  condition: selection and success and not action_wildcard
level: informational
```

What this set structurally cannot do: decide whether the `Allow` and the wildcard share a statement.
That is resolved by parsing in §2 Query 2, and the rules are written to over-match rather than to
guess.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> IAM is a **global service**: run these in `us-east-1`, where its events are recorded.

Run Query 1 first; it produces the policy and version that Query 2 parses.

#### Query 1 — Reconstruct: what was authored, and is it in effect

```bash
REGION="us-east-1"   # IAM events are global-service events, recorded here
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in CreatePolicy CreatePolicyVersion SetDefaultPolicyVersion; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # requestParameters.policyDocument is RAW JSON, not percent-encoded. Only what IAM RETURNS is
      # encoded, so this is parsed directly — decoding it would corrupt a literal %2F.
      | ($r.policyDocument // "") as $doc
      | ($doc | test("\"Action\"\\s*:\\s*\\[?\\s*\"\\*\"")) as $astar
      | ($doc | test("\"Resource\"\\s*:\\s*\\[?\\s*\"\\*\"")) as $rstar
      # Action "*" is administrative. Resource "*" is a shape that many correct policies have.
      | (if .eventName == "SetDefaultPolicyVersion" then "activate(no document)"
         elif $astar and ($r.setAsDefault == true or .eventName == "CreatePolicy") then "ADMIN-LIVE"
         elif $astar then "admin-DORMANT"
         elif $rstar then "resource-* only (normal)"
         else "policy write" end) as $verdict
      | "\(.eventTime)  \(.eventName)  \($verdict)  \(.userIdentity.arn)  " +
        "policy=\($r.policyArn // $r.policyName // "-")  ip=\(.sourceIPAddress)"'
done | sort
```

`admin-DORMANT` is not a lesser version of `ADMIN-LIVE` — it is a different finding. Nothing is
granted, and the correct action is to delete the version rather than to contain a principal, because
the material it creates is exactly what
`../iam.privilege-escalation.default-policy-version-reverted/` describes.

#### Query 2 — Parse the document, because matching it is not enough

```bash
POLICY_ARN="${1:?policy ARN from Query 1 required}"
VERSION="${2:?version id, or run list-policy-versions first}"

aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$VERSION" \
  --query 'PolicyVersion.Document' --output text 2>/dev/null \
| python3 -c '
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
# GetPolicyVersion RETURNS a percent-encoded document. Decode CONDITIONALLY — only input that
# actually begins "%" — because unconditional decoding corrupts a literal %2F in an S3 prefix.
if raw.startswith("%"):
    raw = urllib.parse.unquote(raw)
doc = json.loads(raw)
stmts = doc.get("Statement", [])
if isinstance(stmts, dict):
    stmts = [stmts]
admin = 0
for i, s in enumerate(stmts):
    eff = s.get("Effect")
    act = s.get("Action", []); act = act if isinstance(act, list) else [act]
    res = s.get("Resource", []); res = res if isinstance(res, list) else [res]
    cond = s.get("Condition")
    # THE question a substring match cannot answer: are the Allow and the wildcard in the SAME
    # statement? Here they demonstrably are, because we are inside one statement.
    if eff == "Allow" and "*" in act:
        admin += 1
        scope = "UNCONDITIONAL" if not cond else "conditioned on %s" % list(cond.keys())
        print("[!] stmt %d: Allow on Action:* over Resource=%s — %s" % (i, res[:2], scope))
    elif eff == "Deny" and "*" in act:
        print("[ ] stmt %d: DENY on Action:* — this is a GUARDRAIL, not a grant" % i)
    else:
        print("[ ] stmt %d: %s on %s" % (i, eff, act[:3]))
print()
print("[FAIL] %d administrative Allow statement(s)" % admin if admin
      else "[OK] no Allow on Action:* — the substring match over-matched, as designed")
'
```

This is the step that decides the incident. A `[ ] DENY on Action:*` line means the rule fired on a
guardrail policy, which is a correct over-match and not a false positive to tune away — narrowing
the rule to exclude documents containing `Deny` would also exclude every real policy that has both.

#### Query 3 — Sweep: pre-loaded escalations that already exist

```bash
# Non-default versions granting Action:* are pre-loaded escalations. They appear in no write-time
# alert, because nothing is being written — this is the only way to find the ones already present.
aws iam list-policies --scope Local --query 'Policies[].Arn' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r ARN; do
    [ -z "$ARN" ] && continue
    DEFAULT="$(aws iam get-policy --policy-arn "$ARN" --query 'Policy.DefaultVersionId' --output text 2>/dev/null)"
    aws iam list-policy-versions --policy-arn "$ARN" --query 'Versions[].VersionId' \
      --output text 2>/dev/null | tr '\t' '\n' | while read -r V; do
        [ -z "$V" ] && continue
        aws iam get-policy-version --policy-arn "$ARN" --version-id "$V" \
          --query 'PolicyVersion.Document' --output text 2>/dev/null \
        | python3 -c '
import sys, json, urllib.parse, os
raw = sys.stdin.read().strip()
if not raw: raise SystemExit(0)
if raw.startswith("%"): raw = urllib.parse.unquote(raw)
stmts = json.loads(raw).get("Statement", [])
if isinstance(stmts, dict): stmts = [stmts]
for s in stmts:
    act = s.get("Action", []); act = act if isinstance(act, list) else [act]
    if s.get("Effect") == "Allow" and "*" in act:
        state = "OPERATIVE" if os.environ["V"] == os.environ["DEFAULT"] else "dormant"
        print("[!] %s %s (%s) grants Action:*" % (os.environ["ARN"], os.environ["V"], state))
        break
' ARN="$ARN" V="$V" DEFAULT="$DEFAULT"
      done
  done
```

Run this once before deploying the rules, not only during an incident. Every `dormant` row is an
escalation that already exists and that no write-time detection will ever surface.

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

Look for an `Attach*Policy` call **after** the authoring. A policy that grants `Action: "*"` and is
attached to nothing grants nobody anything; the attachment is what completes the escalation, and it
is covered by `../iam.privilege-escalation.admin-policy-attached/`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The first action depends on Query 1's verdict, and the two cases genuinely diverge: a live
administrative version needs the default reverted, while a dormant one needs the version deleted and
no principal touched.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 confirms an
unconditional `Allow` on `Action: "*"` in an operative version, every principal the policy is
attached to currently has administrative access. Run `list-entities-for-policy` and treat each as
compromised for the duration of the window.

#### Step 1 — For a live version: revert the default

```bash
POLICY_ARN="${1:?policy ARN required}"

aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
  --query 'Versions[].[VersionId,IsDefaultVersion,CreateDate]' --output text 2>/dev/null | sort

echo
echo "[!] Pick the version to revert TO, then verify it before switching — the safe version is not"
echo "    always the highest number, and on this technique the newest version IS the bad one."
echo "    Verification and the revert itself are §3 Step 1 of"
echo "    ../iam.privilege-escalation.default-policy-version-reverted/, which owns that procedure."
```

The revert procedure lives in the sibling directory rather than being duplicated here, because it
is the same operation with the same guard rails and keeping one copy is what stops the two drifting.

#### Step 2 — For a dormant version: delete it

```bash
POLICY_ARN="${1:?policy ARN required}"
BAD_VERSION="${2:?the dormant administrative version}"
OUT="./evidence-$(basename "$POLICY_ARN")-${BAD_VERSION}.json"

# Preserve first: a deleted version's document is unrecoverable from any AWS API.
aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$BAD_VERSION" \
  --output json > "$OUT" 2>/dev/null && echo "[OK] preserved at $OUT"

DEFAULT="$(aws iam get-policy --policy-arn "$POLICY_ARN" --query 'Policy.DefaultVersionId' --output text)"
if [ "$BAD_VERSION" = "$DEFAULT" ]; then
  echo "[FAIL] $BAD_VERSION is the OPERATIVE version — it cannot be deleted while default."
  echo "       Revert first (Step 1), then delete."
else
  aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$BAD_VERSION" \
    && echo "[OK] dormant administrative version $BAD_VERSION deleted"
fi
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

Contain the principal only where Query 2 confirmed a real administrative grant. A `Deny`-only
document is a correct over-match by the rule, and revoking a role over it is the outcome that
teaches a team to switch the rule off.

#### Step 4 — Establish who held the permissions and what they did

```bash
POLICY_ARN="${1:?policy ARN required}"
START="${2:?authoring timestamp from Query 1}"
END="${3:?revert or delete timestamp}"
REGION="us-east-1"

aws iam list-entities-for-policy --policy-arn "$POLICY_ARN" --output json 2>/dev/null \
| jq -r '(.PolicyRoles[].RoleName), (.PolicyUsers[].UserName), (.PolicyGroups[].GroupName)' \
| while read -r NAME; do
    [ -z "$NAME" ] && continue
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

#### Clear the pre-loaded escalations Query 3 found

Every dormant `Action: "*"` version is one call from live, and that call writes no document. This is
the eradication step that generalises beyond the incident: the sweep usually finds versions nobody
remembers authoring, left behind by policies that were tightened without deleting the old text.

#### Decide whether the policy should exist at all

A policy granting `Action: "*"` is rarely the right answer even when it is legitimate. Where the
sweep finds one attached to application roles, the finding is the policy rather than the event that
created it, and replacing it is worth more than any detection here.

#### Separate authoring from activation

`iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` are distinct actions. Granting them to
different principals means a permissive document can be authored but not made operative by the same
identity — which converts the whole technique into the correlated form, and correlations are
detectable where single events are ambiguous.

#### Deny administrative policy authoring outside a break-glass path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyAdministrativePolicyAuthoring",
  "Effect": "Deny",
  "Action": ["iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline that legitimately needs it. Note this denies **all** policy
authoring outside those roles, not only administrative authoring: an SCP cannot inspect a policy
document, so the condition available is on the principal. Test in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify no operative version grants `Action: "*"`

```bash
POLICY_ARN="${1:?policy ARN required}"

CUR="$(aws iam get-policy --policy-arn "$POLICY_ARN" --query 'Policy.DefaultVersionId' --output text)"
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
print("[FAIL] operative version grants Allow on Action:*" if bad
      else "[OK] operative version has no Allow on Action:*")
'
```

#### Verify no dormant version does either

```bash
POLICY_ARN="${1:?policy ARN required}"
FOUND=0

for V in $(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
            --query 'Versions[].VersionId' --output text 2>/dev/null | tr '\t' '\n'); do
  [ -z "$V" ] && continue
  R="$(aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$V" \
        --query 'PolicyVersion.Document' --output text 2>/dev/null \
      | python3 -c '
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
if not raw: print("skip"); raise SystemExit(0)
if raw.startswith("%"): raw = urllib.parse.unquote(raw)
stmts = json.loads(raw).get("Statement", [])
if isinstance(stmts, dict): stmts = [stmts]
print("bad" if [s for s in stmts if s.get("Effect") == "Allow"
      and "*" in (s.get("Action") if isinstance(s.get("Action"), list) else [s.get("Action")])] else "ok")
')"
  [ "$R" = "bad" ] && { echo "[FAIL] version $V still grants Action:*"; FOUND=1; }
done
[ "$FOUND" -eq 0 ] && echo "[OK] no version of $POLICY_ARN grants Action:*"
```

Reverting the default is not recovery while a permissive version survives — that state is exactly
what the sibling technique needs, and it will not produce another authoring event when it is used.

#### Confirm the corrected detection fires

```bash
POLICY_ARN="${1:?a NON-PRODUCTION policy ARN attached to nothing}"

# Exercise the DORMANT case: it is the half the source rule cannot distinguish, and because
# setAsDefault is omitted the version grants nobody anything at any point during the test.
aws iam create-policy-version --policy-arn "$POLICY_ARN" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --query 'PolicyVersion.VersionId' --output text 2>/dev/null \
| while read -r V; do
    echo "[OK] created dormant admin version $V — expect the MEDIUM dormant rule, not the critical one"
    sleep 60
    aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$V" \
      && echo "[OK] test version deleted"
  done
```

If the critical rule fires instead of the medium one, `setAsDefault` is not being read and the whole
live-versus-dormant distinction is not deployed.

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Did the parse confirm an `Allow` on `Action: "*"` in the same statement? | If not, the rule over-matched as designed and the outcome is a tuning note, not an incident. |
| Was the version operative or dormant? | Different remediations entirely — revert a default, or delete a version. Rating them alike is the source rule's main defect. |
| Did Query 3's sweep find pre-loaded versions nobody authored recently? | Those existed before the incident and no write-time detection would ever have surfaced them. |
| Was the policy attached to anything? | An administrative policy attached to nothing grants nobody anything; the attachment is a separate event and a separate use case. |
| Was it `CreatePolicy` rather than `CreatePolicyVersion`? | The pack watches nowhere for the former, so a hit there means the gap was real. |
| Does a multi-Region trail with global service events exist? | Without one, no IAM event reaches any trail and none of this was ever being logged. |

### Recommended Guardrails

**Never alert on `Resource: "*"` alone.** It is what correct policies for `s3:ListAllMyBuckets` and
its siblings look like. The damage is not the volume — it is that responders learn to close this
whole rule family without reading it.

**Read `setAsDefault`.** It is the difference between a draft and an escalation, it is one field, and
without it the alert cannot be rated.

**Sweep for dormant administrative versions on a schedule.** They are invisible to write-time
detection by construction, and they are the raw material for the activation technique.

**Parse policies, do not match them.** Same-statement scoping is the only question that matters and
no substring can answer it. A parser in the alert pipeline removes the entire false-positive class.

**Cover `CreatePolicy`.** A new administrative policy is the same escalation, and it is the earliest
point at which intent is visible because nothing is attached yet.

### Technique Reference

**T1098.003 — Account Manipulation: Additional Cloud Roles.** Verified live at
https://attack.mitre.org/techniques/T1098/003/ on 2026-08-30. The source rule carried **no** MITRE
mapping.

AWS references relied on throughout, all verified 2026-08-30:

- `CreatePolicyVersion` — the `SetAsDefault` semantics that separate a live grant from a dormant
  one, and the five-version limit:
  https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
- `CreatePolicy` — the event the source pack does not watch:
  https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicy.html

Encoding behaviour is authoring rule **A4**: `requestParameters.policyDocument` is raw JSON, while
`GetPolicyVersion` returns a percent-encoded document. Service-wide verified behaviour shared by
every `iam.*` playbook is in `../_ground-truth/iam.md`.

### Residual Risk

**Same-statement scoping is unresolvable at rule level.** Every deployment of these rules will fire
on `Deny`-only guardrail policies. That is correct behaviour, and the mitigation is a parser in the
pipeline rather than a narrower rule — narrowing to exclude documents containing `Deny` would
exclude every real policy that has both an `Allow` and a `Deny`.

**Conditions are not evaluated.** An `Allow` on `Action: "*"` confined by a `Condition` on
`aws:PrincipalOrgID` or an MFA requirement is materially different from an unconditional one. Query
2 reports the condition keys, but neither the rules nor the query judges whether a condition is
sufficient — that remains a human decision.

**An administrative grant can be assembled from non-wildcard actions.** `iam:PassRole` with
`ec2:RunInstances`, or `iam:CreateAccessKey` on a privileged user, reaches administrative access
with no `Action: "*"` anywhere. Nothing here sees that, and it is a materially larger detection
problem than the one this playbook solves.

**AWS-managed policies are out of scope.** Their content is fixed by AWS and cannot be authored by a
customer principal. Attaching `AdministratorAccess` is the equivalent technique for those, and it is
covered in `../iam.privilege-escalation.admin-policy-attached/`.
