# IR Playbook: SNS Topic Opened for Public Subscribe — standing outbound read via `sns:CreateTopic` / `sns:SetTopicAttributes`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Resource-policy exposure (an SNS topic accepts `Subscribe` from `Principal: "*"` with no confining `Condition`, so any caller on the internet can attach their own endpoint and receive every message the topic carries) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** One event creates a standing, unauthenticated read of everything the topic carries, and the read **survives the obvious remediation** — rewriting the policy detaches nothing already attached. The source rule rates it P3, which is too low for a condition whose exploitation window opens immediately and whose moment of exploitation is never logged. It is not P0 only because the actor gains no credential and no control-plane path, and because the ceiling is whatever the topic actually carries: an alarm-notification topic and a customer-PII fan-out topic produce the identical event. Triage on the topic's content. |
| MITRE Tactics | Collection, Persistence |
| MITRE Techniques | T1213, T1098 |
| Services in Scope | SNS, CloudTrail, CloudWatch metrics, IAM, Organizations (RCP), and every downstream system whose data the topic carries |

**What the technique does:** the actor calls `CreateTopic` with an `Attributes.Policy`, or
`SetTopicAttributes` with `AttributeName=Policy`, storing a statement that reads
`"Effect": "Allow"`, `"Principal": {"AWS": "*"}`, an action granting subscribe, and **no
`Condition`**. SNS enforces it immediately. Any principal in any account may then call
`sns:Subscribe` with an endpoint they control — an HTTPS collector, a mailbox, a handset —
and from confirmation onward every message published to the topic is copied to them.

**Detection thesis.** The discriminator is the `Condition` element of the statement carrying
the wildcard principal — **not** the wildcard principal, because AWS's own default topic
policy is `Principal {"AWS": "*"}` over eight actions including `SNS:Subscribe`, made safe by
an `AWS:SourceOwner` condition. The source rule phrase-matches a literal raw JSON never
produces, so it fires on nothing; and it never looks at `Subscribe`, so the exercise of the
grant — the part that actually moves data — was invisible.

---

## 1. Preparation

**Logging & Visibility**

- **CloudTrail management events**, on by default, `eventSource: sns.amazonaws.com`. `CreateTopic`, `SetTopicAttributes`, `AddPermission`, `Subscribe`, `Unsubscribe` and `ConfirmSubscription` are all on AWS's published management-event list.
- **The confirmation gap.** AWS documents that `ConfirmSubscription` and `Unsubscribe`
  invoked in **unauthenticated mode are not logged to CloudTrail** — and the emailed or
  POSTed confirmation link is unauthenticated mode. `Subscribe` is the last observable
  event; whether the subscription went live is answerable only from the live list.
- **Field shapes.** `CreateTopic` carries the policy at `requestParameters.attributes.Policy`;
  `SetTopicAttributes` carries it at `requestParameters.attributeValue`, discriminated by
  `requestParameters.attributeName` — a **flat sibling**, not nested under an `attributes`
  map. `Subscribe` carries `requestParameters.topicArn`, `.protocol` and `.endpoint`, and
  returns `responseElements.subscriptionArn`. The policy is **raw JSON**: percent-encoding is
  a response-side IAM property that does not apply here, and the real hazard is
  pretty-printing, so match with whitespace-tolerant patterns.
- **CloudWatch `AWS/SNS`** — `NumberOfNotificationsDelivered`, dimension `TopicName`. Volume
  delivered only; message bodies appear in no record anywhere.
- **Known IOC baseline.** Keep the expected subscription list per topic on hand — endpoint,
  protocol and owner. Without it, "is this subscriber ours?" has no answer under pressure.

**Alerting (must be pre-configured)**

- **`CreateTopic` storing a policy allowing a subscribe action to `Principal: "*"` with no confining `Condition` → P0**
- **`SetTopicAttributes` with `attributeName=Policy` rewriting a topic to the same shape → P0**
- **A public subscribe grant followed within an hour by a `Subscribe` on the same topic → P0**
- **`Subscribe` to an `http`/`https`/`email`/`email-json`/`sms` endpoint by a principal outside the deployment allowlist → P1**

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
| P0 | `CreateTopic` storing a policy allowing a subscribe action to `Principal: "*"` with no confining `Condition` | CloudTrail (management) | T1213 |
| P0 | `SetTopicAttributes` with `attributeName=Policy` rewriting a topic to the same shape | CloudTrail (management) | T1213 |
| P0 | A public subscribe grant followed within an hour by a `Subscribe` on the same topic | CloudTrail (management) | T1213 |
| P1 | `Subscribe` to an `http`/`https`/`email`/`email-json`/`sms` endpoint by a principal outside the deployment allowlist | CloudTrail (management) | T1213 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A subscription in `ListSubscriptionsByTopic` whose endpoint is absent from the §1 baseline | SNS API (live state) | T1213 |

### Detection Rule Quality Notes

The source rule cannot fire, would fire on every topic if it could, and stops at the grant.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Phrase-matches `Principal:{AWS:*},Action:[SNS:Subscribe]`, and matches `eventName:"createtopic"` in lower case | Zero matches, ever, on both counts. CloudTrail writes `CreateTopic`, and stores the policy as raw JSON — the real bytes are `"Principal":{"AWS":"*"}`, quoted, in client-chosen key order and whitespace | `eventName: 'CreateTopic'`; whitespace-tolerant `\|re` patterns; structural judgement by parsing in the KQL and Query 2 |
| Covers `CreateTopic` only | A topic created clean and opened a minute later by `SetTopicAttributes` is silent — the more common real sequence | Second rule document on `SetTopicAttributes` + `attributeName=Policy` |
| Never inspects `Condition` | Would fire on every console-created topic, because AWS's default policy is `Principal {"AWS":"*"}` over eight actions including `SNS:Subscribe`. Muted within a week | `not confined` block over the SNS confining keys; per-statement evaluation in the KQL and the grader |
| Matches only the literal `SNS:Subscribe` | `"Action": "sns:*"`, `"Action": ["*"]` and an `Allow` with `NotAction` all grant subscribe yet carry no `:Subscribe` substring — full public control reads as clean | `subscribe_action` covers the service wildcard, both scalar and array forms of `"*"`, `NotAction`, and the legacy `:Receive` token |
| Never looks at `Subscribe` | The grant is a misconfiguration; the grant **exercised** is an incident. The rule set could not tell them apart, and the data movement was undetected | Third rule on off-account `Subscribe`, plus a `temporal_ordered` correlation from grant to exercise |

**Recommended detection — a topic created with an unconditioned public subscribe grant.**

```yaml
# SNS topic opened for public subscribe (T1213 / T1098)
#
# The original rule matched `eventName:"createtopic"` — lower case, against a field
# CloudTrail writes as `CreateTopic` — then phrase-matched the policy against the literal
# `Principal:{AWS:*},Action:[SNS:Subscribe]`. That literal occurs in no real event:
# CloudTrail carries `requestParameters.attributes.Policy` as a RAW JSON string, so the
# bytes are `"Principal":{"AWS":"*"}` with quotes, in whatever key order and whitespace the
# client sent. It also covered only CreateTopic, missing the SetTopicAttributes rewrite.
#
# The discriminator is NOT the wildcard principal. AWS's own default topic policy is
# `Principal {"AWS":"*"}` over eight SNS actions including Subscribe — every console-created
# topic carries it — and what makes it safe is the confining Condition. A rule keyed on
# `Principal:*` alone fires on every topic in the account.
#
# WHAT MAKES SUBSCRIBE DIFFERENT FROM PUBLISH, and why these rules do not stop at the grant:
# a subscription OUTLIVES the grant. Removing the public statement does not detach anything
# already attached, so the exposure persists after the obvious fix. Worse, the moment the
# subscription becomes live is INVISIBLE: AWS documents that ConfirmSubscription invoked in
# unauthenticated mode — the emailed or POSTed confirmation link, which is how every HTTP/S
# and email subscription is confirmed — is NOT logged to CloudTrail. So the last rule below
# alerts on the Subscribe call itself, and the correlation ties the grant to its exercise.
title: SNS topic created with an unconditioned public subscribe grant
id: f375c9c0-37b1-401a-9941-513a3df8cbd3
name: sns_public_subscribe_at_create
status: experimental
description: >-
  CreateTopic storing a policy that allows a subscribe-granting action to Principal "*"
  with no principal-scoping Condition. Any internet caller can attach their own endpoint
  and receive every message the topic carries from then on.
references:
  - https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html
  - https://attack.mitre.org/techniques/T1213/
tags:
  - attack.collection
  - attack.persistence
  - attack.t1213
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName: 'CreateTopic'
  public_principal:
    requestParameters.attributes.Policy|re: '"(AWS|Principal)"\s*:\s*(\[[^\]]{0,400})?"\*"'
  subscribe_action:
    requestParameters.attributes.Policy|re: '(?i)("NotAction"|"[^"]{0,40}:(subscribe|receive)"|"sns:\*"|"action"\s*:\s*(\[[^\]]{0,400})?"\*")'
  confined:
    requestParameters.attributes.Policy|re: '(?i)(source(owner|account|arn|vpce?|ip)|principal(orgid|orgpaths|account|arn)|aws:userid|sns:(protocol|endpoint))'
  success:
    errorCode: null
  condition: selection and public_principal and subscribe_action and success and not confined
falsepositives:
  - A deliberately public fan-out topic — allowlist by name, never mute the rule.
level: high
---
title: SNS topic policy replaced with an unconditioned public subscribe grant
id: 17aefb34-3d16-4923-b79d-b8a415d1c715
name: sns_public_subscribe_via_set_attributes
status: experimental
description: >-
  SetTopicAttributes rewriting the Policy attribute of an existing topic to allow a
  subscribe-granting action to Principal "*" with no confining Condition. The original
  rule missed this path entirely — the topic was created correctly and opened afterwards,
  so no CreateTopic event carries the exposure.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html
  - https://attack.mitre.org/techniques/T1213/
tags:
  - attack.collection
  - attack.persistence
  - attack.t1213
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
  public_principal:
    requestParameters.attributeValue|re: '"(AWS|Principal)"\s*:\s*(\[[^\]]{0,400})?"\*"'
  subscribe_action:
    requestParameters.attributeValue|re: '(?i)("NotAction"|"[^"]{0,40}:(subscribe|receive)"|"sns:\*"|"action"\s*:\s*(\[[^\]]{0,400})?"\*")'
  confined:
    requestParameters.attributeValue|re: '(?i)(source(owner|account|arn|vpce?|ip)|principal(orgid|orgpaths|account|arn)|aws:userid|sns:(protocol|endpoint))'
  success:
    errorCode: null
  condition: selection and policy_attribute and public_principal and subscribe_action and success and not confined
falsepositives:
  - Infrastructure-as-code re-applying an intentionally public fan-out topic's policy.
level: high
---
title: SNS subscription created to an endpoint outside AWS identity control
id: 540e8b0f-870e-4fe0-8967-e3e2edb49e45
name: sns_subscribe_offaccount_endpoint
status: experimental
description: >-
  A successful Subscribe whose protocol delivers outside AWS identity control — http,
  https, email, email-json or sms — by a principal outside the deployment allowlist. These
  endpoints are the exfiltration shape: unlike sqs, lambda and firehose they need no IAM
  identity in any account, so the subscriber is whoever controls the URL, mailbox or
  handset. AWS requires ConfirmSubscription for exactly these protocols, and documents
  that an unauthenticated confirmation is NOT logged — so this Subscribe event is the last
  observable moment before the subscription may silently go live.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html
  - https://docs.aws.amazon.com/sns/latest/dg/logging-using-cloudtrail.html
  - https://attack.mitre.org/techniques/T1213/
tags:
  - attack.collection
  - attack.exfiltration
  - attack.t1213
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sns.amazonaws.com'
    eventName: 'Subscribe'
  offaccount_protocol:
    requestParameters.protocol:
      - 'http'
      - 'https'
      - 'email'
      - 'email-json'
      - 'sms'
  known_admins:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/ci-cd'
      - ':role/BreakGlassAdmin'
  success:
    errorCode: null
  condition: selection and offaccount_protocol and success and not known_admins
falsepositives:
  - Operators self-subscribing to an alerting topic by email. Common and legitimate — tune
    by comparing the endpoint against the corporate mail domain, not by dropping the rule.
level: medium
---
title: Public subscribe grant followed by a subscription on the same topic
id: 37c19526-864f-44b7-b379-e4b795d2a4a3
status: experimental
description: >-
  A topic policy opened to an unconfined wildcard subscribe grant, and then a subscription
  created on that same topic within the hour. The grant alone is a misconfiguration; the
  grant followed by its exercise is an incident. Timespan basis — an actor who opens a
  topic in order to read it subscribes immediately, because the whole point is to be
  attached before anyone notices; an hour is generous for that and short enough that an
  unrelated legitimate subscription is unlikely to land inside it. Grouped on
  requestParameters.topicArn, which BOTH component rules emit; the CreateTopic rule is
  deliberately not a component, because it carries the topic ARN in responseElements
  instead and would silently never group.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html
  - https://attack.mitre.org/techniques/T1213/
tags:
  - attack.collection
  - attack.t1213
correlation:
  type: temporal_ordered
  rules:
    - sns_public_subscribe_via_set_attributes
    - sns_subscribe_offaccount_endpoint
  group-by:
    - requestParameters.topicArn
  timespan: 1h
level: high
```

`|re` runs over raw event text, so `not confined` is **document-wide**: a policy whose first
statement is confined and whose second is wide open is suppressed. That false negative is
deliberate — the alternative fires on every console-created topic — and it is why the KQL and
`tools/sns_topic_policy_grade.py` judge each statement on its own `Condition`. Nor can any
rule see an `AddPermission` grant, composed server-side. Query 2 covers both.

---

### Key Investigation Queries

> SNS is regional and topic ARNs are region-scoped — run both queries per region. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page**, so Query 1 prints a MORE PAGES line whenever a page was truncated; re-run it with `TOKEN` set.

#### Query 1 — Reconstruct: who opened the topic, and who then subscribed

```bash
REGION="<region>"; START="<ISO8601-start>"; END="<ISO8601-end>"
TOKEN=""      # re-run with TOKEN set to the value any MORE-PAGES line below prints
for EN in CreateTopic SetTopicAttributes AddPermission Subscribe; do
  PAGE=$(aws cloudtrail lookup-events --region "$REGION" --output json --max-results 50 \
           --lookup-attributes AttributeKey=EventName,AttributeValue="$EN" \
           --start-time "$START" --end-time "$END" ${TOKEN:+--next-token "$TOKEN"} 2>&1)
  if ! printf '%s' "$PAGE" | jq -e 'has("Events")' >/dev/null 2>&1; then
    echo "[!] INCONCLUSIVE $EN — lookup-events returned no Events key: $PAGE"; continue
  fi
  printf '%s' "$PAGE" | jq -r --arg en "$EN" '(.Events[].CloudTrailEvent | fromjson
    | select(.eventSource == "sns.amazonaws.com")
    | {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       ip: .sourceIPAddress, err: (.errorCode // "none"),
       topicArn: (.responseElements.topicArn // .requestParameters.topicArn // "unknown"),
       protocol: (.requestParameters.protocol // "-"),
       endpoint: (.requestParameters.endpoint // "-"), subArn: (.responseElements.subscriptionArn // "-"),
       doc: (.requestParameters.attributes.Policy // .requestParameters.attributeValue // "")}),
    (if .NextToken then "[!] MORE PAGES for \($en) — TOKEN=\(.NextToken)" else empty end)'
done
```

A non-empty `doc` is the exact policy stored. On `Subscribe` rows `endpoint` is the IOC —
compare it against the §1 baseline — and a `protocol` of `http`, `https`, `email`,
`email-json` or `sms` means the subscriber needs no IAM identity in any account. `subArn` of
`pending confirmation` means not-yet-live **at that instant only**; it says nothing about now
and is absent entirely when the caller passed `ReturnSubscriptionArn=true`. `topicArn`,
`caller` and `endpoint` feed every step below.

#### Query 2 — Inspect: grade every live topic policy, then every live subscription

```bash
REGION="<region>"; OUT="/tmp/sns_topics_$REGION.ndjson"
if bash tools/sns_collect_topic_policies.sh "$REGION" > "$OUT"; then
  OWN=$(aws sts get-caller-identity --query Account --output text 2>&1)
  printf '%s' "$OWN" | grep -qE '^[0-9]{12}$' \
    || echo "[!] account id unresolved ($OWN) — the EXTERNAL/INTERNAL verdicts are unreliable"
  ORG_ACCOUNTS="$OWN" python3 tools/decode_policy_documents.py < "$OUT"     # WHO holds it
  python3 tools/sns_topic_policy_grade.py --require subscribe < "$OUT"      # WHAT it permits
  echo "grader exit=$?  (0 clean / 1 open / 2 inconclusive)"
  # The live subscription list is the ONLY source that survives the unlogged-confirmation
  # gap. ListSubscriptionsByTopic always returns a Subscriptions key for a topic that
  # exists, so an absent key is a failed call, never a topic with no subscribers.
  for T in $(jq -r '.grantee' "$OUT"); do
    S=$(aws sns list-subscriptions-by-topic --region "$REGION" --topic-arn "$T" --output json 2>&1)
    if printf '%s' "$S" | jq -e 'has("Subscriptions")' >/dev/null 2>&1; then
      printf '%s' "$S" | jq -r --arg t "$T" '.Subscriptions[]
        | "\($t)  \(.Protocol)  \(.Endpoint)  owner=\(.Owner)  \(.SubscriptionArn)"'
    else
      echo "[!] INCONCLUSIVE $T — list-subscriptions-by-topic failed: $S"
    fi
  done
else
  echo "[!] INCONCLUSIVE — policy collection failed; nothing here is a clean result."
fi
```

Read the passes together. The decoder answers *who* — but its `auto` mode does **not** carry
`aws:SourceOwner` in `TRUST_CONFINERS`, so it prints `[!] PUBLIC` on AWS's own default topic
policy; re-read every `[!]` line for that key first. The grader answers *what*: any
`[!] PUBLIC SUBSCRIBE` or `[!] PUBLIC NOTACTION` is a live grant. The subscription listing is
the authoritative exposure: an `Owner` that is not your account id is a cross-account
subscriber, `PendingConfirmation` never completed, and any `Endpoint` absent from the §1
baseline is the §4 work-list.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="CreateTopic SetTopicAttributes Subscribe"
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

Detach the rogue subscriptions **first**, then close the policy — reversing that order leaves
the attacker attached while the policy fix looks like success. Capture the current policy
before overwriting it: `SetTopicAttributes` replaces it wholesale and SNS keeps no history.

> Run under the **break-glass responder credentials**, not the principal under investigation.

#### Step 1 — Detach the rogue subscribers, then close the topic

```bash
REGION="<region>"; TOPIC="<topic-arn-from-Query-1>"
ROGUE_ARNS="<subscription-arns-from-Query-2>"     # space separated, never a bare placeholder
OWN=$(aws sts get-caller-identity --query Account --output text 2>&1)
EVIDENCE="/tmp/sns_policy_before_$(basename "$TOPIC").json"

for SUB in $ROGUE_ARNS; do
  case "$SUB" in
    arn:aws:sns:*) aws sns unsubscribe --region "$REGION" --subscription-arn "$SUB" \
                     && echo "[OK] detached $SUB" ;;
    *) echo "[!] $SUB is not a subscription ARN (PendingConfirmation cannot be unsubscribed) — skipped" ;;
  esac
done

BEFORE=$(aws sns get-topic-attributes --region "$REGION" --topic-arn "$TOPIC" --output json 2>&1)
if printf '%s' "$BEFORE" | jq -e '.Attributes.Policy' >/dev/null 2>&1; then
  printf '%s' "$BEFORE" | jq -r '.Attributes.Policy' > "$EVIDENCE"; echo "[OK] preserved $EVIDENCE"
else
  echo "[!] INCONCLUSIVE — cannot read the current policy; do NOT overwrite it yet: $BEFORE"
fi
# Restore the owner-only shape AWS documents as the default topic policy.
if [ -s "$EVIDENCE" ] && printf '%s' "$OWN" | grep -qE '^[0-9]{12}$'; then
  POLICY=$(printf '{"Version":"2008-10-17","Id":"__default_policy_ID","Statement":[{"Sid":"__default_statement_ID","Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:GetTopicAttributes","SNS:SetTopicAttributes","SNS:AddPermission","SNS:RemovePermission","SNS:DeleteTopic","SNS:Subscribe","SNS:ListSubscriptionsByTopic","SNS:Publish"],"Resource":"%s","Condition":{"StringEquals":{"AWS:SourceOwner":"%s"}}}]}' "$TOPIC" "$OWN")
  aws sns set-topic-attributes --region "$REGION" --topic-arn "$TOPIC" \
    --attribute-name Policy --attribute-value "$POLICY"
else
  echo "[!] SKIPPED the policy write — evidence capture or account lookup failed above."
fi
```

#### Step 2 — Contain the principal

```bash
CALLER="<caller-arn-from-Query-1>"
FREEZE='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["sns:CreateTopic","sns:SetTopicAttributes","sns:AddPermission","sns:Subscribe"],"Resource":"*"}]}'
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

- **Sweep every region** — re-run Query 2 account-wide, because a scripted grant applies the
  same document to every topic `ListTopics` returns and the alert names only the first. Every
  topic it touched needs its subscription list compared against the §1 baseline, not just the
  one that alerted.
- **Treat the topic's entire content as disclosed** for the window from the grant to the
  detach. Message bodies are recorded nowhere, so scope by what the *publishers* sent, not by
  a log search: enumerate the producers and their payload schema, and escalate on the fields
  they carry — credentials, tokens, PII, internal hostnames.
- **Rotate anything the topic carried that is a secret** — a one-time passcode delivered to a
  rogue SMS subscriber is spent, and an API key in a notification body is now the attacker's.
  Then **set `AuthenticateOnUnsubscribe`** on every future confirmation: left at its default
  of false, an unauthenticated unsubscribe succeeds unlogged, so an actor holding a token can
  silently detach your legitimate subscribers.
- **Right-size the permission** — see the guardrail bullets in §6.
- **Remove the emergency deny once clean** — `delete-user-policy` or `delete-role-policy` for
  `IR-SNS-Freeze`. Containment could have attached either, so check both paths, and confirm
  with the §5 assertion rather than by assuming the delete succeeded.

---

## 5. Recovery

### Restore Clean State

#### Verify no live topic policy grants subscribe to an unconfined wildcard principal

```bash
REGION="<region>"; OUT="/tmp/sns_recovery_$REGION.ndjson"
# The signal survives the remediation: SNS always stores a Policy attribute, so this check can
# still emit an open verdict after the fix — [FAIL] is reachable, not zero by construction.
if ! bash tools/sns_collect_topic_policies.sh "$REGION" > "$OUT"; then   # exits 2 on read failure
  echo "[!] INCONCLUSIVE — could not enumerate every topic policy; nothing is certified clean"
else
  python3 tools/sns_topic_policy_grade.py --require subscribe < "$OUT"
  case $? in
    0) echo "[OK] no unconfined public subscribe grant on any topic in $REGION" ;;
    1) echo "[FAIL] a topic still grants subscribe to an unconfined wildcard principal" ;;
    *) echo "[!] INCONCLUSIVE — the grader could not read every policy; not clean" ;;
  esac
fi
```

#### Verify no unrecognised subscriber is still attached

```bash
REGION="<region>"; OUT="/tmp/sns_recovery_$REGION.ndjson"
OWN=$(aws sts get-caller-identity --query Account --output text 2>&1)
# The grant check above certifies nothing on its own: closing the policy detaches NOBODY.
# This is the assertion that matters, and it can still fail after the remediation — the
# subscription list is exactly the thing §3 did not change.
if ! printf '%s' "$OWN" | grep -qE '^[0-9]{12}$'; then
  echo "[!] INCONCLUSIVE — account id unresolved ($OWN); cannot judge subscriber ownership"
elif [ ! -s "$OUT" ]; then
  echo "[!] INCONCLUSIVE — no collected topic list; re-run the check above first"
else
  FOREIGN=0
  for T in $(jq -r '.grantee' "$OUT"); do
    S=$(aws sns list-subscriptions-by-topic --region "$REGION" --topic-arn "$T" --output json 2>&1)
    # ListSubscriptionsByTopic always returns a Subscriptions key for a topic that exists,
    # so an absent key is a failed call, never a topic with no subscribers.
    if ! printf '%s' "$S" | jq -e 'has("Subscriptions")' >/dev/null 2>&1; then
      echo "[!] INCONCLUSIVE $T — could not list subscriptions: $S"; FOREIGN=2; continue
    fi
    HITS=$(printf '%s' "$S" | jq -r --arg own "$OWN" --arg t "$T" \
      '.Subscriptions[] | select(.Owner != $own)
       | "[FAIL] \($t) still has subscriber \(.Endpoint) (\(.Protocol)) owned by \(.Owner)"')
    [ -n "$HITS" ] && { printf '%s\n' "$HITS"; FOREIGN=1; }
  done
  case "$FOREIGN" in
    0) echo "[OK] every remaining subscriber on every topic is owned by $OWN" ;;
    1) echo "[FAIL] cross-account subscribers remain — detach them before closing the incident" ;;
    *) echo "[!] INCONCLUSIVE — at least one topic could not be read; nothing is certified" ;;
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
echo '   {"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"SNS:Subscribe"}]}'
echo 'MUST NOT fire on: that document plus "Condition":{"StringEquals":'
echo '   {"AWS:SourceOwner":"<own-account-id>"}}   <- AWS default topic policy'
echo 'MUST NOT fire on: a public grant of sns:Publish only — that is the sibling use case.'
echo 'CORRELATION must fire on: SetTopicAttributes(Policy, public subscribe) then Subscribe on'
echo '   the SAME requestParameters.topicArn within 1h.'
echo 'EXPECTED FN: a 2-statement doc, FIRST confined, SECOND unconditioned public subscribe.'
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A topic policy was stored with `Principal: "*"` and no confining `Condition` | No preventive control on the resource-policy write path; `sns:SetTopicAttributes` on `Resource: "*"` was reachable by a non-administrative principal |
| A subscription attached under the grant survived the policy fix | Remediation was modelled as a configuration change, but the exposure is a *relationship* — closing the policy detaches nobody |
| The moment the subscription went live was never recorded | AWS does not log `ConfirmSubscription` in unauthenticated mode, which is how every HTTP/S and email subscription is confirmed. Only live enumeration answers it |
| No baseline of expected subscribers existed | "Is this endpoint ours?" had to be answered from memory during the incident |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Resource control policy fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// An SCP cannot do this job: SCPs constrain only principals managed by accounts inside your
// organisation, and the actor here is by definition outside it. An RCP attaches resource-side.
// The PrincipalIsAWSService guard is mandatory — without it this denies CloudWatch alarms and
// every other service-initiated call, which is an outage. Failure direction: Deny +
// StringNotEquals denies everything that does not match, so a mistyped org id takes the topic
// offline; Deny + StringEquals would permit everything instead.
{ "Sid": "DenySubscribeOutsideOrg", "Effect": "Deny", "Principal": "*",
  "Action": ["sns:Subscribe", "sns:Receive"], "Resource": "*",
  "Condition": {
    "StringNotEqualsIfExists": { "aws:PrincipalOrgID": "<your-org-id>" },
    "Bool": { "aws:PrincipalIsAWSService": "false" } } }
```

- Constrain the delivery **shape** as well as the principal: `sns:Protocol` and `sns:Endpoint`
  are the SNS condition keys AWS documents for restricting what a subscriber may attach. A
  topic that only fans out to SQS should carry `"StringEquals": {"sns:Protocol": "sqs"}`,
  making an emailed exfiltration endpoint impossible rather than merely detectable.
- Diff `ListSubscriptionsByTopic` against the §1 baseline on a schedule — that diff is the
  only control that survives the unlogged-confirmation gap.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1213 — Data from Information Repositories (Collection); T1098 — Account Manipulation for the policy write (Persistence) |
| Primary API | `sns:CreateTopic` with `Attributes.Policy`, or `sns:SetTopicAttributes` with `AttributeName=Policy`; then `sns:Subscribe`. Event source `sns.amazonaws.com`, **management** plane, on by default, verified against AWS's published management-event list |
| Key discriminator | The `Condition` element of the statement carrying `Principal: "*"`. Its absence is the finding; the wildcard alone is AWS's own default |
| "Was it used" pivot | `Subscribe` **is** a management event, so `lookup-events` answers directly — but corroborate with `ListSubscriptionsByTopic`, the only source that survives the unlogged confirmation, and with CloudWatch `NumberOfNotificationsDelivered` by `TopicName` |
| Blast radius | Every message published from confirmation onward, copied to an endpoint you do not control; plus silent detachment of legitimate subscribers when `AuthenticateOnUnsubscribe` is false |
| Error strings | `AuthorizationError` (403 — SNS does **not** use `AccessDenied`), `InvalidParameter`, `InvalidSecurity`, `InternalError`, `NotFound`; `Subscribe` adds `FilterPolicyLimitExceeded`, `ReplayLimitExceeded`, `SubscriptionLimitExceeded`; `CreateTopic` adds `ConcurrentAccess`, `StaleTag`, `TagLimitExceeded`, `TagPolicy`, `TopicLimitExceeded`. An over-large or malformed policy is `InvalidParameter`, **not** `LimitExceeded` |
| Policy size | AWS publishes no size quota for the SNS *access* policy; the nearest documented SNS policy cap is 30,720 characters, on `DataProtectionPolicy`, a different attribute. Nothing documented approaches CloudTrail's 100 KB `requestParameters` omission threshold, so **no oversized-document companion rule ships** |

### Residual Risk

Every message the topic carried between confirmation and detach has already been delivered to
the attacker's endpoint, and SNS keeps no copy — the disclosure is bounded only by what the
publishers sent, which you must reconstruct from the producers, not from any log. If the
endpoint was a mailbox or a handset, the content is outside every system you control and no
revocation reaches it. Any credential or one-time passcode that transited the topic is spent
and must be rotated whether or not you can prove it was read. A `PendingConfirmation`
subscription cannot be unsubscribed; the token AWS mailed to that endpoint stays valid for two
days and will silently establish delivery if used. And because unauthenticated
`ConfirmSubscription` is never logged, you cannot prove a negative — only that the live list
is clean now.
