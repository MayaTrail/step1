# IR Playbook: SNS Topic Opened for Public Publish — internet-writable message bus via `sns:CreateTopic` / `sns:SetTopicAttributes`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Resource-policy exposure (an SNS topic accepts `Publish` from `Principal: "*"` with no confining `Condition`, so any caller on the internet can inject messages that fan out to every subscriber) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** One event opens an unauthenticated write path into a message bus whose subscribers — Lambda, SQS, HTTPS, email, SMS — process what arrives as if it originated inside the account. There is no confirmation step and no rate limit beyond the account publish quota, so the exposure is live the instant the policy is stored. The source rule rates it P3; that is too low, because P3 means triage-when-convenient for a condition that is either being exploited or not within seconds. It is not P0 only because the actor gains no credential and no control-plane path — the ceiling is whatever the subscribers do with a message. |
| MITRE Tactics | Persistence, Impact |
| MITRE Techniques | T1098, T1565.002 (the source rule maps T1213 / Collection — see the mapping note in `detections/detection_note_t1098.md`) |
| Services in Scope | SNS, CloudTrail, CloudWatch metrics, IAM, Organizations (RCP), and every subscriber service the topic fans out to |

**What the technique does:** the actor calls `CreateTopic` with an `Attributes.Policy`, or
`SetTopicAttributes` with `AttributeName=Policy`, storing a statement that reads
`"Effect": "Allow"`, `"Principal": {"AWS": "*"}`, an action granting publish, and **no
`Condition`**. SNS enforces it immediately. From that instant any principal in any account
may call `sns:Publish` on the topic ARN, and SNS fans each message out to every confirmed
subscription, each of which processes it as if it came from inside the account.

**Detection thesis.** The discriminator is the `Condition` element of the statement carrying
the wildcard principal — **not** the wildcard principal, because AWS's own default topic
policy is `Principal {"AWS": "*"}` over eight actions including `SNS:Publish`, made safe by
an `AWS:SourceOwner` condition, and every console-created topic carries it. The source rule
phrase-matches a literal raw JSON never produces, so it fires on nothing; had it matched, it
would have fired on every topic in the account.

---

## 1. Preparation

**Logging & Visibility**

- **CloudTrail management events**, on by default, `eventSource: sns.amazonaws.com`.
  `CreateTopic`, `SetTopicAttributes`, `AddPermission`, `RemovePermission`, `Subscribe` and
  `DeleteTopic` are all on AWS's published management-event list.
- **Field shapes.** `CreateTopic` carries the policy at `requestParameters.attributes.Policy`;
  `SetTopicAttributes` carries it at `requestParameters.attributeValue`, discriminated by
  `requestParameters.attributeName` — a **flat sibling**, not nested under an `attributes`
  map. `CreateTopic` returns `responseElements.topicArn`, **flat**, per AWS's event example;
  `SetTopicAttributes` and `AddPermission` return `responseElements: null`.
- **The policy in `requestParameters` is raw JSON.** Percent-encoding is a response-side IAM
  property that does not apply here — SNS returns no policy in `responseElements` at all. The
  real hazard is pretty-printing; match with whitespace-tolerant patterns.
- **`sns:Publish` is a CloudTrail DATA event** (`eventCategory: "Data"`,
  `managementEvent: false`, type `AWS::SNS::Topic`), **off by default**. Turn on a data-event
  trail before you need it, or "was the grant used" has no CloudTrail answer — and even then
  `message`/`subject`/`messageAttributes` read `HIDDEN_DUE_TO_SECURITY_REASONS`.
- **CloudWatch `AWS/SNS`** — `NumberOfMessagesPublished`, `NumberOfNotificationsDelivered`
  and `NumberOfNotificationsFailed`, dimension `TopicName`, 1-minute resolution. A topic
  counts as active to CloudWatch for up to six hours after its last API call, so a quiet
  topic that was abused and then abandoned still reports for that window.

**Alerting (must be pre-configured)**

- **`CreateTopic` storing a policy allowing a publish action to `Principal: "*"` with no confining `Condition` → P0**
- **`SetTopicAttributes` with `attributeName=Policy` rewriting a topic to the same shape → P0**
- **`AddPermission` granting `Publish` to an account outside the organisation → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The contents of `known_admins` from the shipped rules. Each is populated before deployment and is the whole tuning cost of the detection.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `CreateTopic` storing a policy allowing a publish action to `Principal: "*"` with no confining `Condition` | CloudTrail (management) | T1098 |
| P0 | `SetTopicAttributes` with `attributeName=Policy` rewriting a topic to the same shape | CloudTrail (management) | T1098 |
| P1 | `AddPermission` granting `Publish` to an account outside the organisation | CloudTrail (management) | T1098 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `NumberOfMessagesPublished` rising against the topic's own 7-day baseline after the grant | CloudWatch (`AWS/SNS`) | T1565.002 |
| P3 | Three or more distinct topic policies rewritten by one non-administrative principal in an hour | CloudTrail (management) | T1098 |
| P3 | Wildcard-principal statement whose `Condition` names an account or org outside your own | CloudTrail (management) | T1098 |

### Detection Rule Quality Notes

The source rule cannot fire, and if it could it would fire on every topic in the account.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Phrase-matches `Principal:{AWS:*},Action:SNS:Publish`, and matches `eventName:"createtopic"` in lower case | Zero matches, ever, on both counts. CloudTrail writes `CreateTopic`, and stores the policy as raw JSON — so the real bytes are `"Principal":{"AWS":"*"}`, quoted, in client-chosen key order and whitespace | `eventName: 'CreateTopic'`; whitespace-tolerant `\|re` patterns; structural judgement by parsing in the KQL and Query 2 |
| Covers `CreateTopic` only | A topic created clean and opened a minute later by `SetTopicAttributes` is silent — and that is the more common real sequence | Second rule document on `SetTopicAttributes` + `attributeName=Policy` |
| Never inspects `Condition` | Would fire on every console-created topic, because AWS's default policy is `Principal {"AWS":"*"}` over eight actions including `SNS:Publish`. Muted within a week | `not confined` block over the SNS confining keys; per-statement evaluation in the KQL and the grader |
| Matches only the literal `SNS:Publish`, and is mapped to T1213 / Collection | `"Action": "sns:*"`, `"Action": ["*"]` and an `Allow` with `NotAction` all grant publish yet carry no `:Publish` substring — full public control reads as clean. And the mapping sends the responder hunting outbound exfiltration when the harm is inbound injection | `publish_action` covers the service wildcard, both scalar and array forms of `"*"`, and `NotAction`; remapped to T1098 for the grant and T1565.002 for the consequence |

**Recommended detection — an SNS topic created with an unconditioned public publish grant.**

```yaml
# SNS topic opened for public publish (T1098 / T1565.002)
#
# The original rule matched `eventName:"createtopic"` — lower case, against a field
# CloudTrail writes as `CreateTopic` — then phrase-matched the policy against the literal
# `Principal:{AWS:*},Action:SNS:Publish`. That literal occurs in no real event: CloudTrail
# carries `requestParameters.attributes.Policy` as a RAW JSON string, so the bytes are
# `"Principal":{"AWS":"*"}` with quotes, in whatever key order and whitespace the client
# sent. It also covered only CreateTopic, so a topic created clean and opened a minute
# later by SetTopicAttributes was invisible.
#
# The discriminator is NOT the wildcard principal. AWS's own default topic policy is
# `Principal {"AWS":"*"}` over eight SNS actions including Publish — every console-created
# topic carries it — and what makes it safe is the confining Condition (`AWS:SourceOwner`,
# `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID`, `aws:sourceVpce`,
# `sns:Protocol`, `sns:Endpoint`). A rule keyed on `Principal:*` alone fires on every topic
# in the account and is muted inside a week.
#
# `|re` rather than `|contains`, for three reasons that are all correctness, not style:
#   * the real request-side hazard is WHITESPACE, not encoding — a policy sent with
#     `--policy-document file://` is pretty-printed, and `\s*` absorbs that where a
#     fixed-spacing substring does not;
#   * `(?i)` handles the action-prefix case, which is genuinely unstable — AWS's default
#     policy writes `SNS:Publish`, AddPermission generates `sns:Publish`;
#   * it closes the array forms. `"Action": ["*"]` and `"Principal": {"AWS": ["1","*"]}`
#     have no substring that is not also inside an innocuous policy.
title: SNS topic created with an unconditioned public publish grant
id: 79571f1f-c865-4d1c-8e0f-d2c27dfbf5b7
name: sns_public_publish_at_create
status: experimental
description: >-
  CreateTopic storing a policy that allows a publish-granting action to Principal "*" with
  no principal-scoping Condition. Any internet caller can inject messages into the topic.
references:
  - https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.impact
  - attack.t1098
  - attack.t1565.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName: 'CreateTopic'
  public_principal:
    requestParameters.attributes.Policy|re: '"(AWS|Principal)"\s*:\s*(\[[^\]]{0,400})?"\*"'
  publish_action:
    requestParameters.attributes.Policy|re: '(?i)("NotAction"|"[^"]{0,40}:publish"|"sns:\*"|"action"\s*:\s*(\[[^\]]{0,400})?"\*")'
  confined:
    requestParameters.attributes.Policy|re: '(?i)(source(owner|account|arn|vpce?|ip)|principal(orgid|orgpaths|account|arn)|aws:userid|sns:(protocol|endpoint))'
  success:
    errorCode: null
  condition: selection and public_principal and publish_action and success and not confined
falsepositives:
  - A deliberately open ingest topic — allowlist by name, never mute the rule.
level: high
---
title: SNS topic policy replaced with an unconditioned public publish grant
id: b4d57555-54ea-4126-ba55-ba605aeeb7ea
name: sns_public_publish_via_set_attributes
status: experimental
description: >-
  SetTopicAttributes rewriting the Policy attribute of an existing topic to allow a
  publish-granting action to Principal "*" with no confining Condition. This is the path
  the original rule missed entirely — the topic was created correctly and opened
  afterwards, so no CreateTopic event carries the exposure.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.impact
  - attack.t1098
  - attack.t1565.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName: 'SetTopicAttributes'
  policy_attribute:
    requestParameters.attributeName: 'Policy'
  public_principal:
    requestParameters.attributeValue|re: '"(AWS|Principal)"\s*:\s*(\[[^\]]{0,400})?"\*"'
  publish_action:
    requestParameters.attributeValue|re: '(?i)("NotAction"|"[^"]{0,40}:publish"|"sns:\*"|"action"\s*:\s*(\[[^\]]{0,400})?"\*")'
  confined:
    requestParameters.attributeValue|re: '(?i)(source(owner|account|arn|vpce?|ip)|principal(orgid|orgpaths|account|arn)|aws:userid|sns:(protocol|endpoint))'
  success:
    errorCode: null
  condition: selection and policy_attribute and public_principal and publish_action and success and not confined
falsepositives:
  - Infrastructure-as-code re-applying an intentionally open ingest topic's policy.
    Allowlist by topic ARN, not by principal.
level: high
---
title: SNS topic policy rewritten by a principal outside the topic-administration set
id: 51a63854-6ab9-45ad-b451-c9f98b434072
name: sns_topic_policy_write_unexpected_principal
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. Any successful write to a
  topic's Policy attribute by a principal outside the deployment and administration
  allowlist. Carries the success filter so a DENIED first step plus a legitimate second
  step cannot raise the correlation below.
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
    eventSource: 'sns.amazonaws.com'
    eventName: 'SetTopicAttributes'
  policy_attribute:
    requestParameters.attributeName: 'Policy'
  known_admins:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/ci-cd'
      - ':role/BreakGlassAdmin'
  success:
    errorCode: null
  condition: selection and policy_attribute and success and not known_admins
level: low
---
title: Repeated SNS topic policy rewrites by one principal
id: 612a7a8e-a153-4949-a221-629e39df602d
status: experimental
description: >-
  Three or more DISTINCT topics' policies rewritten by the same non-administrative
  principal inside an hour. Threshold basis — a human editing a policy edits one topic;
  a fan-out across three or more distinct topics in an hour is a scripted sweep, which is
  how a public grant gets applied account-wide rather than to a single topic. Tune the
  count to the number of topics one legitimate deploy re-applies.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.persistence
  - attack.t1098
correlation:
  type: value_count
  rules:
    - sns_topic_policy_write_unexpected_principal
  group-by:
    - userIdentity.arn
  field: requestParameters.topicArn
  timespan: 1h
  condition:
    gte: 3
level: medium
```

`|re` still runs over raw event text, so `not confined` is **document-wide**: a policy whose
first statement is confined and whose second is wide open is suppressed. That false negative
is deliberate — the alternative fires on every console-created topic — and it is why the KQL
and `tools/sns_topic_policy_grade.py` judge each statement on its own `Condition`. Nor can
any rule see an `AddPermission` grant, whose statement is composed server-side and never
reaches `requestParameters`. Query 2 covers both.

---

### Key Investigation Queries

> SNS is regional and topic ARNs are region-scoped — run both queries per region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page**; Query 1 pages on `NextToken` rather than silently truncating.

#### Query 1 — Reconstruct: who opened which topic, when, with what document

```bash
REGION="<region>"; START="<ISO8601-start>"; END="<ISO8601-end>"

for EN in CreateTopic SetTopicAttributes AddPermission; do
  TOKEN=""
  while : ; do
    PAGE=$(aws cloudtrail lookup-events --region "$REGION" --output json --max-results 50 \
             --lookup-attributes AttributeKey=EventName,AttributeValue="$EN" \
             --start-time "$START" --end-time "$END" ${TOKEN:+--next-token "$TOKEN"} 2>&1)
    if ! printf '%s' "$PAGE" | jq -e 'has("Events")' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $EN — lookup-events returned no Events key: $PAGE"; break
    fi
    printf '%s' "$PAGE" | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.eventSource == "sns.amazonaws.com")
      | {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
         ip: .sourceIPAddress, ua: .userAgent, err: (.errorCode // "none"),
         topicArn: (.responseElements.topicArn // .requestParameters.topicArn // "unknown"),
         attributeName: (.requestParameters.attributeName // "-"),
         doc: (.requestParameters.attributes.Policy // .requestParameters.attributeValue // "")}'
    TOKEN=$(printf '%s' "$PAGE" | jq -r '.NextToken // empty')
    [ -n "$TOKEN" ] || break
  done
done
```

Any record with `attributeName` of `Policy`, or a non-empty `doc` on a `CreateTopic`, is a
policy write. `err` of `AuthorizationError` is a denied attempt — SNS never emits
`AccessDenied` — and a run of those from one `caller` is the permission probing that preceded
the write. `AddPermission` rows carry an empty `doc` by design. `topicArn` and `caller` feed
every step below.

#### Query 2 — Inspect: grade every live topic policy in the region

```bash
REGION="<region>"; OUT="/tmp/sns_topics_$REGION.ndjson"
if bash tools/sns_collect_topic_policies.sh "$REGION" > "$OUT"; then
  OWN=$(aws sts get-caller-identity --query Account --output text 2>&1)
  printf '%s' "$OWN" | grep -qE '^[0-9]{12}$' \
    || echo "[!] account id unresolved ($OWN) — the EXTERNAL/INTERNAL verdicts are unreliable"
  # WHO holds the grant. Shape-safe on Statement / Principal / Action.
  ORG_ACCOUNTS="$OWN" python3 tools/decode_policy_documents.py < "$OUT"
  # WHAT the grant permits, judged per statement, and the only pass that recognises
  # aws:SourceOwner — the key AWS's own default topic policy uses.
  python3 tools/sns_topic_policy_grade.py --require publish < "$OUT"
  echo "grader exit=$?  (0 clean / 1 open / 2 inconclusive)"
else
  echo "[!] INCONCLUSIVE — policy collection failed; nothing here is a clean result."
fi
```

Read both passes together. The decoder answers *who* — but its `auto` mode does **not** carry
`aws:SourceOwner` in `TRUST_CONFINERS`, so it prints `[!] PUBLIC` on AWS's own default topic
policy; re-read every `[!]` line for that key first. The grader answers *what*: any
`[!] PUBLIC PUBLISH` or `[!] PUBLIC NOTACTION` is a live exposure, and each `[i] CONFINED`
needs its condition value checked against `$OWN`.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CreateTopic SetTopicAttributes"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "sns.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Grouped by caller rather than by resource,
because the question eradication needs answered is *how much of this is one actor's work* — a
per-resource list cannot say. `access_key` is emitted because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` whether or not it happened; the preamble's caveat applies.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN: one credential is used across many sessions, and
the key identifies the credential. The per-service grouping answers what this playbook cannot —
whether this technique was the objective or one stop on a tour. A service in that list with no
business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID, so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Capture the offending document **before** you overwrite it: `SetTopicAttributes` replaces the
policy wholesale and SNS keeps no version history, so the evidence exists only until you fix
it. Closing the policy stops new injection and nothing else: it recalls no delivered message
and detaches no subscription created while the grant was open.

> Run under the **break-glass responder credentials**, not the principal under investigation.

#### Step 1 — Preserve, then close the topic

```bash
REGION="<region>"; TOPIC="<topic-arn-from-Query-1>"
OWN=$(aws sts get-caller-identity --query Account --output text 2>&1)
EVIDENCE="/tmp/sns_policy_before_$(basename "$TOPIC").json"
BEFORE=$(aws sns get-topic-attributes --region "$REGION" --topic-arn "$TOPIC" --output json 2>&1)
if printf '%s' "$BEFORE" | jq -e '.Attributes.Policy' >/dev/null 2>&1; then
  printf '%s' "$BEFORE" | jq -r '.Attributes.Policy' > "$EVIDENCE"; echo "[OK] preserved $EVIDENCE"
else
  echo "[!] INCONCLUSIVE — cannot read the current policy; do NOT overwrite it yet: $BEFORE"
fi

# Restore the owner-only shape AWS documents as the default topic policy.
if [ -s "$EVIDENCE" ] && printf '%s' "$OWN" | grep -qE '^[0-9]{12}$'; then
  cat > /tmp/sns_owner_only.json <<EOF
{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{
 "Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},
 "Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission",
   "SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe",
   "SNS:ListSubscriptionsByTopic","SNS:Publish"],
 "Resource":"$TOPIC","Condition":{"StringEquals":{"AWS:SourceOwner":"$OWN"}}}]}
EOF
  aws sns set-topic-attributes --region "$REGION" --topic-arn "$TOPIC" \
    --attribute-name Policy --attribute-value "file:///tmp/sns_owner_only.json"
else
  echo "[!] SKIPPED the policy write — evidence capture or account lookup failed above."
fi
```

#### Step 2 — Contain the principal

```bash
CALLER="<caller-arn-from-Query-1>"
FREEZE='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sns:CreateTopic","sns:SetTopicAttributes","sns:AddPermission","sns:Publish","sns:Subscribe"],"Resource":"*"}]}'
case "$CALLER" in
  *":user/"*)          # IAM user: the name is $NF. Disable keys before attaching the deny.
    UNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $NF}')
    for K in $(aws iam list-access-keys --user-name "$UNAME" \
                 --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
      aws iam update-access-key --user-name "$UNAME" --access-key-id "$K" --status Inactive
    done
    aws iam put-user-policy --user-name "$UNAME" --policy-name IR-SNS-Freeze \
      --policy-document "$FREEZE" && echo "[OK] contained IAM user $UNAME" ;;
  *":assumed-role/"*)  # Role name is the 2nd '/' segment; $NF is the SESSION name.
    RNAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $2}')
    aws iam put-role-policy --role-name "$RNAME" --policy-name IR-SNS-Freeze \
      --policy-document "$FREEZE" && echo "[OK] contained IAM role $RNAME" ;;
  *)
    echo "[!] $CALLER is root, federated or a service principal — contain manually." ;;
esac
```

---

## 4. Eradication

### Remove Attacker Access

- **Sweep every region.** Re-run Query 2 account-wide: a scripted grant applies the same
  document to every topic `ListTopics` returns, and the alert names only the first.
- **Enumerate subscriptions on every affected topic** —
  `aws sns list-subscriptions-by-topic --topic-arn "$TOPIC"`. A publish grant creates none,
  but if the statement also carried `SNS:Subscribe` or a wildcard the actor had both, and a
  confirmed subscription survives the policy fix. Remove unknown ones with `aws sns unsubscribe`.
- **Treat every subscriber as having processed untrusted input** for the exposure window from
  Query 1. Nothing marks an attacker-authored message and the body is recorded nowhere, so
  this is a code review of the consumers, not a log search.
- **Right-size the permission.** `sns:SetTopicAttributes`, `sns:AddPermission` and
  `sns:CreateTopic` on `Resource: "*"` are what made this reachable; AWS's guidance is to deny
  the first two together with `sns:RemovePermission` to remove the ability to change topic
  permissions at all.
- **Remove the emergency deny once clean** — `delete-user-policy` or `delete-role-policy` for
  `IR-SNS-Freeze`. Containment could have attached either, so check both paths, and confirm
  with the assertion in §5 rather than by assuming the delete succeeded.

---

## 5. Recovery

### Restore Clean State

#### Verify no live topic policy grants publish to an unconfined wildcard principal

```bash
REGION="<region>"; OUT="/tmp/sns_recovery_$REGION.ndjson"
# The signal survives the remediation: SNS always stores a Policy attribute, so this check can
# still emit an open verdict after the fix — [FAIL] is reachable, not zero by construction.
if ! bash tools/sns_collect_topic_policies.sh "$REGION" > "$OUT"; then   # exits 2 on read failure
  echo "[!] INCONCLUSIVE — could not enumerate every topic policy; nothing is certified clean"
else
  python3 tools/sns_topic_policy_grade.py --require publish < "$OUT"
  case $? in
    0) echo "[OK] no unconfined public publish grant on any topic in $REGION" ;;
    1) echo "[FAIL] a topic still grants publish to an unconfined wildcard principal" ;;
    *) echo "[!] INCONCLUSIVE — the grader could not read every policy; not clean" ;;
  esac
fi
```

#### Verify the emergency deny policy was removed from whichever principal type carried it

```bash
CALLER="<caller-arn-from-Query-1>"
case "$CALLER" in
  *":user/"*)         KIND=user; NAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $NF}') ;;
  *":assumed-role/"*) KIND=role; NAME=$(printf '%s' "$CALLER" | awk -F'/' '{print $2}') ;;
  *)                  KIND=other; NAME="$CALLER" ;;
esac
case "$KIND" in
  user) POLS=$(aws iam list-user-policies --user-name "$NAME" --output json 2>&1) ;;
  role) POLS=$(aws iam list-role-policies --role-name "$NAME" --output json 2>&1) ;;
  *)    POLS="" ;;
esac
# list-*-policies always returns a PolicyNames array for a principal that exists, so an
# absent key is a failed call — it must NOT reach the same branch as "policy removed".
if [ "$KIND" = "other" ]; then
  echo "[!] INCONCLUSIVE — $CALLER is root, federated or a service principal; check by hand"
elif ! printf '%s' "$POLS" | jq -e 'has("PolicyNames")' >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE — could not list inline policies for $KIND $NAME: $POLS"
elif printf '%s' "$POLS" | jq -e '.PolicyNames | index("IR-SNS-Freeze")' >/dev/null 2>&1; then
  echo "[FAIL] IR-SNS-Freeze is still attached to $KIND $NAME"
else
  echo "[OK] IR-SNS-Freeze removed from $KIND $NAME"
fi
```

#### Confirm the corrected detection fires

```bash
echo 'MUST fire on:     CreateTopic, sns.amazonaws.com, no errorCode, attributes.Policy ='
echo '   {"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"SNS:Publish"}]}'
echo 'MUST NOT fire on: that document plus "Condition":{"StringEquals":'
echo '   {"AWS:SourceOwner":"<own-account-id>"}}   <- AWS default topic policy'
echo 'MUST NOT fire on: a public grant of sns:Subscribe only — that is the sibling use case.'
echo 'EXPECTED FN, by design: a 2-statement doc, FIRST confined, SECOND unconditioned public'
echo '   publish. The regex reads the whole document; the grader judges per statement.'
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A topic policy was stored with `Principal: "*"` and no confining `Condition` | No preventive control on the resource-policy write path; `sns:SetTopicAttributes` on `Resource: "*"` was reachable by a non-administrative principal |
| The exposure was live from the instant of the write | Topic policies take effect immediately, with no approval and no propagation delay — a detective control alone can never close that gap |
| Neither whether the grant was exercised, nor what was injected, could be answered | No data-event trail on `AWS::SNS::Topic`, so `Publish` was never logged; and even with one, `message`/`subject`/`messageAttributes` are recorded as `HIDDEN_DUE_TO_SECURITY_REASONS` — content is unrecoverable by any configuration |
| The alert could not say whether the grant was intentional | No recorded inventory of topics that are public by design, so every occurrence needed a human to ask around before it could be rated |
| A wildcard principal confined only by `aws:SourceArn` still read as public | The rule tested the principal and not the condition, so a legitimately confined policy and an open one produced the same finding |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Resource control policy fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// An SCP cannot do this job: SCPs constrain only principals managed by accounts inside your
// organisation, and the actor here is by definition outside it. An RCP attaches resource-side.
// The PrincipalIsAWSService guard is mandatory — without it this denies CloudWatch alarms and
// every other service-initiated publish, which is an outage. Failure direction: Deny +
// StringNotEquals denies everything that does not match, so a mistyped org id takes the topic
// offline; Deny + StringEquals would permit everything instead.
{ "Sid": "DenyPublishOutsideOrg", "Effect": "Deny", "Principal": "*",
  "Action": ["sns:Publish", "sns:Subscribe"], "Resource": "*",
  "Condition": {
    "StringNotEqualsIfExists": { "aws:PrincipalOrgID": "<your-org-id>" },
    "Bool": { "aws:PrincipalIsAWSService": "false" } } }
```

- Deny `sns:AddPermission`, `sns:RemovePermission` and `sns:SetTopicAttributes` in every
  identity policy but the deployment role — AWS names those three together as the set that
  must be denied to remove the ability to change topic permissions.
- Enable a CloudTrail data-event trail on `resources.type = AWS::SNS::Topic` for topics
  carrying anything sensitive. Without it, "was the grant used" has no answer beyond a metric
  count, and the message bodies are unrecoverable either way.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098 — Account Manipulation (the grant, Persistence); T1565.002 — Data Manipulation: Transmitted Data Manipulation (the consequence, Impact) |
| Primary API | `sns:CreateTopic` with `Attributes.Policy`, or `sns:SetTopicAttributes` with `AttributeName=Policy`; `sns:AddPermission` for the cross-account form. Event source `sns.amazonaws.com`, **management** plane, on by default, verified against AWS's published management-event list |
| Key discriminator | The `Condition` element of the statement carrying `Principal: "*"`. Its absence is the finding; the wildcard alone is AWS's own default |
| "Was it used" pivot | CloudWatch `AWS/SNS` `NumberOfMessagesPublished`, dimension `TopicName`. **Not** `lookup-events` — `Publish` is a data event, off by default, and returns zero forever without a data-event trail |
| Blast radius | Every confirmed subscription — Lambda, SQS, HTTPS, email, SMS — each processing attacker input as trusted; plus publish-quota consumption and, for SMS, direct cost |
| Error strings | `AuthorizationError` (403 — SNS does **not** use `AccessDenied`), `InvalidParameter`, `InvalidSecurity`, `InternalError`, `NotFound`; `CreateTopic` adds `ConcurrentAccess`, `StaleTag`, `TagLimitExceeded`, `TagPolicy`, `TopicLimitExceeded`. An over-large or malformed policy is `InvalidParameter`, **not** `LimitExceeded` |
| Policy size | AWS publishes no size quota for the SNS *access* policy; the nearest documented SNS policy cap is 30,720 characters, and that is on `DataProtectionPolicy`, a different attribute. Nothing documented approaches CloudTrail's 100 KB `requestParameters` omission threshold, so **no oversized-document companion rule ships** |

### Residual Risk

Restoring the policy stops new injection and nothing else. Every message published during the
exposure window has already been delivered: SNS has no recall, no replay that separates
attacker traffic, and no record of the body. Downstream consumers that acted on those
messages have already acted — rows written, workflows started, email and SMS sent to your own
subscribers under your display name. If the statement also carried `SNS:Subscribe` or a
wildcard, any subscription confirmed before the fix is still attached and still receiving —
closing the policy unsubscribes nobody. And if the actor held stolen credentials rather than
exploiting a misconfiguration, nothing in §3 beyond the identity containment touches that
credential: the SNS grant was the symptom, and the account compromise that produced it is a
separate investigation.
