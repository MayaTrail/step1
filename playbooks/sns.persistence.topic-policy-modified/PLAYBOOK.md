# IR Playbook: SNS Topic Policy Modified After Creation — `AddPermission` and `SetTopicAttributes`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence — an existing topic's access policy is changed so that a principal outside the account can subscribe to its messages or publish into it |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical for a wildcard principal, or an external grant followed by a subscription; high for an `AddPermission` naming another account or a policy sweep; medium for a data protection policy change. The source rule is P4 and cannot fire in most accounts. |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1098 (primary); T1213 (the subscribe side) |
| Services in Scope | SNS, CloudTrail |

**What the technique does:** the actor opens an existing topic. Granting `sns:Subscribe` to their own
account turns every message published to the topic into a feed they receive; granting `sns:Publish`
lets them inject messages into whatever consumes it. Neither requires creating anything.

**Why the usual reflexes miss it.** The first is the rule's name: *SNS Access Policy Has Changed*
matches `PutDataProtectionPolicy`, which governs redaction inside message bodies rather than access.
The second is that AWS has closed message data protection to new customers, so the rule cannot fire in
most accounts at all. The third is that the two sibling rules covering public topic policies only
match `CreateTopic` — a topic made public afterwards is unmatched. The fourth is expecting a policy
document: `AddPermission` grants an account access with two parameters and no JSON.

**Detection thesis:** cover all three access-policy paths, test the submitted document rather than the
call, and keep the data protection policy for what it actually is.

**Adjacent playbooks.** Topics created public are
`../sns.collection.sns-topic-was-created-with-public-publish-permissions/` and
`../sns.collection.sns-topic-was-created-with-public-subscribe-permissions/`. Encryption changes are
`../sns.impact.server-side-encryption-for-aws-sns-topics-was-disabled/` and
`../sns.impact.a-less-secure-server-side-encryption-policy-created/`. Topic deletion is
`../sns.stealth.topic-deleted/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `SetTopicAttributes` and `AddPermission` are
control-plane and logged by default, and the **submitted policy document** is in `requestParameters`
— which is the only record of what the policy became, since SNS keeps no version history.

**A stored copy of every topic's access policy**, refreshed on a schedule. `SetTopicAttributes`
replaces rather than merges, so the only way to know what was removed is to have kept what was there.

**A list of the account ids that legitimately appear in topic policies.** Cross-account SNS is common
and legitimate; the finding is an id that is not on the list, and that judgement should not be made
under time pressure.

**Alerting (must be pre-configured)**

- **A topic policy submitted with a wildcard principal → P0**
- **`AddPermission` naming an account outside this one, followed by a `Subscribe` → P0**
- **`AddPermission` naming an account outside this one → P1**
- **`PutDataProtectionPolicy` in an account that still holds the feature → P2**

**Response Tooling**

An IAM principal that can call `sns get-topic-attributes`, `sns set-topic-attributes`,
`sns remove-permission` and `sns list-subscriptions-by-topic` outside the change pipeline.

**Known IOC Baselines**

The provisioning roles that write topic policies. Compliance tooling that standardises policies across
topics is the dominant false positive for the sweep correlation.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `SetTopicAttributes` submitting a `Policy` with a wildcard principal | CloudTrail | T1098 |
| P0 | `AddPermission` naming an external account, followed by a `Subscribe` to an endpoint outside the account | CloudTrail | T1213 |
| P1 | `AddPermission` naming an account outside this one | CloudTrail | T1098 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | Three or more topic policies changed by one principal within thirty minutes | Correlation rule | T1098 |
| P2 | A replaced policy naming an IAM ARN from another account | CloudTrail | T1098 |
| P2 | `PutDataProtectionPolicy` in an account that still holds the feature | CloudTrail | T1213 |

### Detection Rule Quality Notes

The source rule is one immediate query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Named *SNS Access Policy Has Changed*, matches `PutDataProtectionPolicy` | A data protection policy governs redaction inside message bodies, not who may publish or subscribe. Two different features | Both covered, each described as what it is |
| The matched feature is closed to new customers | AWS states message data protection "is no longer available to new customers", so in most accounts the rule cannot fire — while the rule list reports the access policy as covered | Stated explicitly, and the access-policy paths detected separately |
| `SetTopicAttributes` with `AttributeName=Policy` unmatched anywhere in the source set | A topic made public after creation produces no alert. The two sibling rules only match `CreateTopic` | A rule testing the submitted document |
| `AddPermission` unmatched anywhere in the source set | It grants an account access with two parameters and no policy document, which makes it the simplest path and the one to expect | A rule filtering on the granted account id |
| No volume dimension | One deliberate change and a walk across every topic look the same | A three-topics-in-thirty-minutes correlation |

**What the source gets right:** the event name is correctly cased and errors are excluded, which two
sibling SNS rules in this source set do not manage — see `../_ground-truth/sns.md` §5.

**Recommended detection — all three access-policy paths, and the data protection policy kept honest.**

```yaml
# SNS topic policy modified after creation (T1098)
#
# THE RULE'S NAME AND ITS LOGIC DESCRIBE DIFFERENT FEATURES. It is called *SNS Access Policy Has
# Changed* and it matches `PutDataProtectionPolicy` — a policy that audits or de-identifies sensitive
# data inside message BODIES, and which has nothing to do with who may publish or subscribe.
#
# AND THE FEATURE IT DOES MATCH IS CLOSED. AWS: "Amazon SNS message data protection is no longer
# available to new customers." In most accounts the API cannot be called at all, so the rule has never
# fired — while the rule list reports the access policy as covered.
#
# THE ACCESS POLICY HAS THREE PATHS AND TWO ARE UNCOVERED ACROSS THE WHOLE SOURCE SET.
# `CreateTopic` with a public Policy attribute is matched by two sibling rules. `SetTopicAttributes`
# with AttributeName=Policy and `AddPermission` are matched by nothing, so a topic made public AFTER
# creation produces no alert. AddPermission is the call to expect: it grants an account access with
# two parameters and no JSON document at all. See ../../_ground-truth/sns.md §1.
title: SNS topic opened to an external principal via AddPermission
id: c61d46cc-4c7d-4543-9445-dcf352e82f53
status: experimental
description: >-
  AddPermission adds a statement to a topic's access control policy for named AWS accounts. It needs
  no policy document — an account id and an action name are enough — which makes it the simplest way
  to open an existing topic, and it is matched nowhere in the source set.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_AddPermission.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sns.amazonaws.com
    eventName: AddPermission
    errorCode: null
  # POPULATE with this account's own id so that same-account grants do not dominate. A grant naming
  # any other account is the finding.
  filter_own_account:
    requestParameters.aWSAccountId|contains: '111122223333'
  condition: selection and not filter_own_account
falsepositives:
  - Deliberate cross-account integrations, which are a small and enumerable set and belong in an
    explicit account allowlist rather than in the removal of this document
level: high
---
# SetTopicAttributes REPLACES the whole policy document, so a principal is added by appearing and
# removed by being left out. The wildcard test is on the submitted value.
title: SNS topic policy replaced with a wildcard principal
id: be778e4f-180c-4b83-a549-ffc363a94f93
status: experimental
description: >-
  SetTopicAttributes with AttributeName Policy submitted a document granting a wildcard principal.
  The two sibling rules in this source set only match CreateTopic, so a topic made public after
  creation is otherwise undetected.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
  - attack.t1213
logsource:
  product: aws
  service: cloudtrail
detection:
  # All four keys are on the SAME event: CloudTrail writes eventSource, eventName and the request
  # body of one API call into one record. ANDing them is correct.
  selection:
    eventSource: sns.amazonaws.com
    eventName: SetTopicAttributes
    requestParameters.attributeName: Policy
    requestParameters.attributeValue|contains: '"AWS":"*"'
  # justified: no threshold and no allowlist. A topic policy naming a wildcard principal is the
  # finding on its first occurrence, and no automation legitimately publishes one.
  condition: selection
falsepositives:
  - A topic deliberately opened to the world for a public notification feed, which should be a named
    exception rather than a filter
level: critical
---
name: sns_topic_policy_changed
title: SNS topic access policy replaced
id: 32b4e592-6c48-4173-ba4a-f9d026f5897a
status: experimental
description: >-
  SetTopicAttributes changed a topic's Policy attribute. Informational alone — the document replaces
  rather than merges, so the event carries the new policy and never says what was removed. Base rule
  for the correlation below.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sns.amazonaws.com
    eventName:
      - SetTopicAttributes
      - AddPermission
      - RemovePermission
    errorCode: null
  filter_provisioning:
    userIdentity.arn|contains:
      - 'PlatformAutomation'
      - 'iac-deploy'
  condition: selection and not filter_provisioning
falsepositives:
  - Infrastructure provisioning under a role not yet in the allowlist
level: informational
---
# The data protection policy — what the source rule actually matches. Kept, correctly described, and
# rated for what it does: removing it unredacts message bodies for every existing subscriber.
title: SNS message data protection policy replaced or removed
id: ffac0546-31c1-48ab-a3d3-c56f5a9efb02
status: experimental
description: >-
  PutDataProtectionPolicy changed the policy that audits or de-identifies sensitive data inside
  message bodies. This is not the access policy. AWS has closed the feature to new customers, so in
  most accounts this cannot fire at all — which is why it must not be relied on as access-policy
  coverage.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_PutDataProtectionPolicy.html
  - https://attack.mitre.org/techniques/T1213/
tags:
  - attack.collection
  - attack.t1213
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sns.amazonaws.com
    eventName: PutDataProtectionPolicy
    errorCode: null
  # justified: no threshold. Accounts that still hold this feature have very few such policies and
  # change them rarely, so any change is worth reading; accounts that do not hold it will never see
  # this document fire.
  condition: selection
falsepositives:
  - The small number of accounts that adopted message data protection before it closed and still
    maintain policies through a pipeline
level: medium
---
# Several topics re-policied by one principal is a sweep rather than a change.
title: SNS topic policies changed across multiple topics by one principal
id: f7ce6ac4-b192-45f7-998e-47e8d69a5476
status: experimental
description: >-
  One principal changed the access policy on three or more topics within thirty minutes. A single
  change is routine; a walk across the account's topics is access being granted at scale.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
correlation:
  type: value_count
  rules:
    - sns_topic_policy_changed
  group-by:
    - userIdentity.arn
  timespan: 30m
  condition:
    gte: 3
    field: requestParameters.topicArn
falsepositives:
  - A compliance remediation applying a standard policy across every topic, identifiable from a change
    record naming the same topic ARNs
level: high
```

What this set structurally cannot do: tell you what the policy said before. SNS keeps no version
history, so a *removal* — a principal dropped from a replaced document — is visible only against a
stored baseline, which is why §1 asks for one.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> SNS is **regional**. `SetTopicAttributes` and `AddPermission` are control-plane and logged by
> default.

Run Query 1 first; it establishes which path was used and who was granted what.

#### Query 1 — Reconstruct: which path, and who was granted access

```bash
REGION="${AWS_REGION:-us-east-1}"
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in SetTopicAttributes AddPermission RemovePermission PutDataProtectionPolicy Subscribe; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg acct "$ACCT" '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # attributeValue carries the full policy document as RAW JSON on the request side. The
      # percent-encoded convention applies to response elements, not here.
      | ($r.attributeValue // "") as $pol
      | [ (if ($pol | test("\"AWS\":\\s*\"\\*\"")) or ($pol | test("\"Principal\":\\s*\"\\*\"")) then "WILDCARD" else empty end),
          (if ($pol | test("arn:aws:iam::")) and (($pol | test("arn:aws:iam::" + $acct)) | not) then "EXTERNAL-ARN" else empty end),
          (if (($r.aWSAccountId // "" | tostring) != "") and (($r.aWSAccountId | tostring | test($acct)) | not) then "EXTERNAL-ACCOUNT" else empty end) ] as $flags
      | "\(.eventTime)  \(.eventName)  attr=\($r.attributeName // "-")  " +
        "topic=\(($r.topicArn // "-") | split(":") | last)  " +
        "granted=\($r.aWSAccountId // "-" | tostring)  actions=\($r.actionName // "-" | tostring)  " +
        "[\($flags | join(","))]  by=\(.userIdentity.arn)"'
done | sort
```

An `EXTERNAL-ACCOUNT` line from `AddPermission` is the simplest form of this technique — no policy
document was needed. A `Subscribe` shortly afterwards is the channel actually being used.

#### Query 2 — Read every topic policy as it stands now

```bash
REGION="${AWS_REGION:-us-east-1}"
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"

aws sns list-topics --region "$REGION" --query 'Topics[].TopicArn' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    POL="$(aws sns get-topic-attributes --topic-arn "$T" --region "$REGION" \
            --query 'Attributes.Policy' --output text 2>/dev/null)"
    [ -z "$POL" ] && continue
    if printf '%s' "$POL" | grep -qE '"(AWS|Principal)":[[:space:]]*"\*"'; then
      echo "[FAIL] ${T##*:} — wildcard principal"
    elif printf '%s' "$POL" | grep -q 'arn:aws:iam::' && ! printf '%s' "$POL" | grep -q "arn:aws:iam::${ACCT}"; then
      echo "[!] ${T##*:} — names an IAM ARN outside this account"
    elif printf '%s' "$POL" | grep -qE '"AWS":[[:space:]]*"[0-9]{12}"' && ! printf '%s' "$POL" | grep -q "\"${ACCT}\""; then
      echo "[!] ${T##*:} — names an account id outside this one"
    else
      echo "[OK] ${T##*:}"
    fi
  done

echo
echo "[!] A wildcard principal is not automatically a finding: SNS's default policy for a topic uses"
echo "    a wildcard constrained by a SourceOwner or SourceArn condition. Read the Condition block"
echo "    before treating a [FAIL] as public — an unconstrained wildcard is the one that matters."
```

#### Query 3 — Who is subscribed, and where do the messages go

```bash
REGION="${AWS_REGION:-us-east-1}"
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"

aws sns list-topics --region "$REGION" --query 'Topics[].TopicArn' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    aws sns list-subscriptions-by-topic --topic-arn "$T" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg acct "$ACCT" --arg t "${T##*:}" '.Subscriptions[]
        | if (.Owner != $acct) or ((.Endpoint // "") | test($acct) | not) and (.Protocol | test("lambda|sqs"))
          then "[!] \($t)  \(.Protocol)  \(.Endpoint)  owner=\(.Owner)"
          else "[OK] \($t)  \(.Protocol)  \(.Endpoint)" end'
  done

echo
echo "[!] Email and HTTPS endpoints are the ones to read closely — an address or URL the organisation"
echo "    does not own receives every message published to that topic from the moment it confirms."
echo "[!] PendingConfirmation in place of a subscription ARN means the endpoint has NOT yet accepted."
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

The same pattern against other services — `PutBucketPolicy`, `SetQueueAttributes`,
`ModifyDBSnapshotAttribute` — is one actor opening every resource policy they can reach, which is a
larger finding than any one of them.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Remove the grant, then remove the subscription. In that order: reversing it lets the actor
re-subscribe while the policy is still open.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 3 shows a confirmed
subscription to an endpoint outside the organisation, every message published to that topic since
confirmation has been delivered. Treat the message content as disclosed and scope from what the topic
carries, not from the subscription's age.

#### Step 1 — Preserve the policy, then revoke the grant

```bash
TOPIC="${1:?topic ARN}"
ACCOUNT="${2:?account id to revoke, from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

aws sns get-topic-attributes --topic-arn "$TOPIC" --region "$REGION" \
  --query 'Attributes.Policy' --output text 2>/dev/null > "./evidence-snspolicy-${TOPIC##*:}.json" \
  && echo "[OK] current policy preserved at ./evidence-snspolicy-${TOPIC##*:}.json"

# RemovePermission removes a statement by its Sid. AddPermission sets the Sid to the label the caller
# supplied, which Query 1 shows; if the grant came from a replaced policy document instead, revert
# with set-topic-attributes using the stored baseline rather than this call.
LABEL="${3:-}"
if [ -n "$LABEL" ]; then
  aws sns remove-permission --topic-arn "$TOPIC" --label "$LABEL" --region "$REGION" >/dev/null 2>&1 \
    && echo "[OK] statement '$LABEL' removed" \
    || echo "[FAIL] no statement labelled '$LABEL' — the grant may be inside a replaced document"
else
  echo "[!] No label supplied. Revert from the stored baseline:"
  echo "    aws sns set-topic-attributes --topic-arn $TOPIC --attribute-name Policy \\"
  echo "      --attribute-value file://<baseline>.json --region $REGION"
fi
```

#### Step 2 — Remove subscriptions that should not exist

```bash
TOPIC="${1:?topic ARN}"
REGION="${AWS_REGION:-us-east-1}"

aws sns list-subscriptions-by-topic --topic-arn "$TOPIC" --region "$REGION" --output json 2>/dev/null \
| jq -r '.Subscriptions[] | "\(.SubscriptionArn)\t\(.Protocol)\t\(.Endpoint)"' \
| while IFS="$(printf '\t')" read -r ARN PROTO EP; do
    [ -z "$ARN" ] && continue
    if [ "$ARN" = "PendingConfirmation" ]; then
      echo "[OK] $PROTO $EP — never confirmed, nothing was delivered; it expires on its own"
      continue
    fi
    read -r -p "Unsubscribe $PROTO $EP ? [y/N] " ANS
    [ "$ANS" = "y" ] && aws sns unsubscribe --subscription-arn "$ARN" --region "$REGION" >/dev/null 2>&1 \
      && echo "[OK] unsubscribed $EP"
  done
```

A `PendingConfirmation` subscription received nothing — the endpoint never accepted. That distinction
is the difference between a disclosure and an attempt, and it costs one field to check.

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

#### Step 4 — Establish what the topic carries

The severity of this incident is entirely a function of the message content. A topic carrying
deployment notifications is a nuisance; one carrying password-reset links, order details or security
findings is a disclosure. Read a sample of recent messages from a legitimate subscriber — the
subscription list in Query 3 names them — rather than guessing from the topic's name.

---

## 4. Eradication

### Remove Attacker Access

#### Constrain wildcard principals with a condition

SNS's own default topic policy uses a wildcard principal constrained by `aws:SourceOwner`. That
pattern is fine; an **unconstrained** wildcard is not. Auditing for a wildcard without a `Condition`
block is a much better test than auditing for a wildcard.

#### Deny policy changes outside the provisioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenySNSTopicPolicyChangesOutsideProvisioning",
  "Effect": "Deny",
  "Action": ["sns:SetTopicAttributes", "sns:AddPermission", "sns:RemovePermission"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone. Note that `sns:SetTopicAttributes` also governs encryption, delivery policy and archive
settings, so this denial is broader than the access policy alone. Test in a non-production OU first.

#### Back up topic policies on a schedule

SNS keeps no version history. A daily `get-topic-attributes` across every topic, committed somewhere,
is what makes a *removal* visible — the event carries only the new document.

#### Stop relying on the data protection rule for access coverage

It watches a different feature, and one that AWS has closed to new customers. Any coverage report
listing it as access-policy detection is wrong, and the fix is a rule per path rather than a rename.

---

## 5. Recovery

### Restore Clean State

#### Verify no topic is open to an unexpected principal

```bash
REGION="${AWS_REGION:-us-east-1}"
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
# POPULATE with account ids that legitimately appear in topic policies.
ALLOWED="$ACCT 999988887777"

aws sns list-topics --region "$REGION" --query 'Topics[].TopicArn' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    POL="$(aws sns get-topic-attributes --topic-arn "$T" --region "$REGION" \
            --query 'Attributes.Policy' --output text 2>/dev/null)"
    [ -z "$POL" ] && continue
    BAD=0
    for ID in $(printf '%s' "$POL" | grep -oE '[0-9]{12}' | sort -u); do
      OK=0
      for A in $ALLOWED; do [ "$ID" = "$A" ] && OK=1; done
      [ "$OK" -eq 0 ] && { echo "[FAIL] ${T##*:} — names account $ID"; BAD=1; }
    done
    [ "$BAD" -eq 0 ] && echo "[OK] ${T##*:}"
  done
```

#### Verify every subscription is one you recognise

```bash
REGION="${AWS_REGION:-us-east-1}"

aws sns list-subscriptions --region "$REGION" --output json 2>/dev/null \
| jq -r '.Subscriptions[]
    | if .SubscriptionArn == "PendingConfirmation" then "[OK] pending  \(.Protocol)  \(.Endpoint)"
      elif (.Protocol | test("email|https|http")) then "[!] confirmed \(.Protocol)  \(.Endpoint) — read this endpoint"
      else "[OK] \(.Protocol)  \(.Endpoint)" end'
```

Email and HTTP/S endpoints are singled out because they are the ones that can point anywhere. A
Lambda or SQS endpoint is an ARN, and its account id is checked by the previous script.

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"
TOPIC="${1:?a NON-PRODUCTION topic ARN}"
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"

# Exercise the ADDPERMISSION path — the one matched nowhere in the source set. Granting to your OWN
# account changes nothing about who can reach the topic, so this is safe, and it should still produce
# the base-rule event.
aws sns add-permission --topic-arn "$TOPIC" --label "detection-test-$$" \
  --aws-account-id "$ACCT" --action-name Subscribe --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] AddPermission issued — expect the informational base rule, NOT the external-grant alert"

sleep 20
aws sns remove-permission --topic-arn "$TOPIC" --label "detection-test-$$" --region "$REGION" \
  >/dev/null 2>&1 && echo "[OK] statement removed"
echo "[!] If nothing fired at all, AddPermission is unmonitored — which is the source set's state."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Which of the three access-policy paths was used? | Two of them are matched nowhere in the source set, and `AddPermission` needs no policy document. |
| Was a subscription created after the grant? | Opening the topic is preparation; the subscription is the channel being used. |
| Was the subscription confirmed or still pending? | A pending subscription received nothing — it is an attempt rather than a disclosure. |
| Was the wildcard constrained by a condition? | SNS's own default policy uses a constrained wildcard; only an unconstrained one is public. |
| What does the topic actually carry? | The severity is a function of the message content, not the topic's name. |
| Did the same principal open other resource policies? | One actor opening every policy they can reach is a larger finding than any single topic. |

### Recommended Guardrails

**Detect all three paths.** Creation-time coverage plus a rule named for the access policy that
watches a different feature adds up to no coverage at all.

**Watch `AddPermission` specifically.** It is the simplest way to open a topic and it needs no policy
syntax, which makes it the likeliest and the least monitored.

**Audit wildcards without a `Condition`, not wildcards.** SNS's own default policy uses a constrained
wildcard, so a naive wildcard check produces noise and trains people to ignore it.

**Back up topic policies daily.** SNS keeps no history, and a removal is only visible as a diff.

**Check `PendingConfirmation` before declaring a disclosure.** It is one field and it decides whether
anything was delivered.

### Technique Reference

**T1098 — Account Manipulation.** Verified live at https://attack.mitre.org/techniques/T1098/ on
2026-08-31. Granting a principal standing access to a topic preserves that access independently of
any credential, which is what this technique names. It matches the mapping used by
`../sns.collection.sns-topic-was-created-with-public-publish-permissions/`.

**T1213 — Data from Information Repositories.** Verified live 2026-08-31. It covers the subscribe
side — a topic subscribed by an outsider is a standing feed of its messages — and matches the mapping
used by the subscribe sibling.

AWS references relied on throughout, all verified 2026-08-31:

- `AddPermission` — "adds a statement to a topic's access control policy, granting access for the
  specified AWS accounts": https://docs.aws.amazon.com/sns/latest/api/API_AddPermission.html
- `SetTopicAttributes` — the `Policy` attribute as "the policy that defines who can access your
  topic": https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
- Message data protection — "no longer available to new customers":
  https://docs.aws.amazon.com/sns/latest/dg/message-data-protection.html

Service-wide verified behaviour shared by the `sns.*` playbooks authored against it is in
`../_ground-truth/sns.md`.

### Residual Risk

**SNS keeps no policy history.** A principal removed from a replaced document leaves no trace in the
event, which carries only the new policy. Without a stored baseline, removals are invisible.

**A confirmed subscription has already delivered.** Unsubscribing stops future messages and returns
nothing that was sent, so the disclosure window runs from confirmation, not from discovery.

**Cross-account SNS is normal.** The finding is an account id that is not expected, which means this
playbook's precision depends entirely on the allowlist in §1 being maintained.

**`sns:SetTopicAttributes` is one permission for several settings.** Denying it to protect the access
policy also removes the ability to change encryption, delivery policy and archive settings, so the
guardrail in §4 has an operational cost that has to be planned for.
